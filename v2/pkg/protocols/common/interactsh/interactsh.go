package interactsh

import (
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/karlseguin/ccache"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
)

// Client is a wrapped client for interactsh server.
type Client struct {
	dotHostname string
	// interactsh is a client for interactsh server.
	interactsh *client.Client
	// requests is a stored cache for interactsh-url->request-event data.
	requests *ccache.Cache
	// interactions is a stored cache for interactsh-interaction->interactsh-url data
	interactions *ccache.Cache

	options          *Options
	eviction         time.Duration
	pollDuration     time.Duration
	cooldownDuration time.Duration

	generated uint32 // decide to wait if we have a generated url
	matched   bool
}

var (
	defaultInteractionDuration = 60 * time.Second
	interactshURLMarker        = "{{interactsh-url}}"
)

// Options contains configuration options for interactsh nuclei integration.
type Options struct {
	// ServerURL is the URL of the interactsh server.
	ServerURL string
	// CacheSize is the numbers of requests to keep track of at a time.
	// Older items are discarded in LRU manner in favor of new requests.
	CacheSize int64
	// Eviction is the period of time after which to automatically discard
	// interaction requests.
	Eviction time.Duration
	// CooldownPeriod is additional time to wait for interactions after closing
	// of the poller.
	ColldownPeriod time.Duration
	// PollDuration is the time to wait before each poll to the server for interactions.
	PollDuration time.Duration
	// Output is the output writer for nuclei
	Output output.Writer
	// IssuesClient is a client for issue exporting
	IssuesClient *reporting.Client
	// Progress is the nuclei progress bar implementation.
	Progress progress.Progress
}

const defaultMaxInteractionsCount = 5000

// New returns a new interactsh server client
func New(options *Options) (*Client, error) {
	parsed, err := url.Parse(options.ServerURL)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse server url")
	}

	interactsh, err := client.New(&client.Options{
		ServerURL:         options.ServerURL,
		PersistentSession: false,
	})
	if err != nil {
		return nil, errors.Wrap(err, "could not create client")
	}
	configure := ccache.Configure()
	configure = configure.MaxSize(options.CacheSize)
	cache := ccache.New(configure)

	interactionsCfg := ccache.Configure()
	interactionsCfg = interactionsCfg.MaxSize(defaultMaxInteractionsCount)
	interactionsCache := ccache.New(interactionsCfg)

	interactClient := &Client{
		interactsh:       interactsh,
		eviction:         options.Eviction,
		interactions:     interactionsCache,
		dotHostname:      "." + parsed.Host,
		options:          options,
		requests:         cache,
		pollDuration:     options.PollDuration,
		cooldownDuration: options.ColldownPeriod,
	}

	interactClient.interactsh.StartPolling(interactClient.pollDuration, func(interaction *server.Interaction) {
		item := interactClient.requests.Get(interaction.UniqueID)
		if item == nil {
			// If we don't have any request for this ID, add it to temporary
			// lru cache so we can correlate when we get an add request.
			gotItem := interactClient.interactions.Get(interaction.UniqueID)
			if gotItem == nil {
				interactClient.interactions.Set(interaction.UniqueID, []*server.Interaction{interaction}, defaultInteractionDuration)
			} else if items, ok := gotItem.Value().([]*server.Interaction); ok {
				items = append(items, interaction)
				interactClient.interactions.Set(interaction.UniqueID, items, defaultInteractionDuration)
			}
			return
		}
		request, ok := item.Value().(*RequestData)
		if !ok {
			return
		}
		_ = interactClient.processInteractionForRequest(interaction, request)
	})
	return interactClient, nil
}

// processInteractionForRequest processes an interaction for a request
func (c *Client) processInteractionForRequest(interaction *server.Interaction, data *RequestData) bool {
	data.Event.InternalEvent["interactsh_protocol"] = interaction.Protocol
	data.Event.InternalEvent["interactsh_request"] = interaction.RawRequest
	data.Event.InternalEvent["interactsh_response"] = interaction.RawResponse
	result, matched := data.Operators.Execute(data.Event.InternalEvent, data.MatchFunc, data.ExtractFunc)
	if !matched || result == nil {
		return false // if we don't match, return
	}
	c.requests.Delete(interaction.UniqueID)

	if data.Event.OperatorsResult != nil {
		data.Event.OperatorsResult.Merge(result)
	} else {
		data.Event.OperatorsResult = result
	}
	data.Event.Results = data.MakeResultFunc(data.Event)

	for _, result := range data.Event.Results {
		result.Interaction = interaction
		_ = c.options.Output.Write(result)
		if !c.matched {
			c.matched = true
		}
		c.options.Progress.IncrementMatched()

		if c.options.IssuesClient != nil {
			if err := c.options.IssuesClient.CreateIssue(result); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
	}
	return true
}

// URL returns a new URL that can be interacted with
func (c *Client) URL() string {
	atomic.CompareAndSwapUint32(&c.generated, 0, 1)
	return c.interactsh.URL()
}

// Close closes the interactsh clients after waiting for cooldown period.
func (c *Client) Close() bool {
	if c.cooldownDuration > 0 && atomic.LoadUint32(&c.generated) == 1 {
		time.Sleep(c.cooldownDuration)
	}
	c.interactsh.StopPolling()
	c.interactsh.Close()
	return c.matched
}

// ReplaceMarkers replaces the {{interactsh-url}} placeholders to actual
// URLs pointing to interactsh-server.
//
// It accepts data to replace as well as the URL to replace placeholders
// with generated uniquely for each request.
func (c *Client) ReplaceMarkers(data, interactshURL string) string {
	if !strings.Contains(data, interactshURLMarker) {
		return data
	}
	replaced := strings.NewReplacer("{{interactsh-url}}", interactshURL).Replace(data)
	return replaced
}

// MakeResultEventFunc is a result making function for nuclei
type MakeResultEventFunc func(wrapped *output.InternalWrappedEvent) []*output.ResultEvent

// RequestData contains data for a request event
type RequestData struct {
	MakeResultFunc MakeResultEventFunc
	Event          *output.InternalWrappedEvent
	Operators      *operators.Operators
	MatchFunc      operators.MatchFunc
	ExtractFunc    operators.ExtractFunc
}

// RequestEvent is the event for a network request sent by nuclei.
func (c *Client) RequestEvent(interactshURL string, data *RequestData) {
	id := strings.TrimSuffix(interactshURL, c.dotHostname)

	interaction := c.interactions.Get(id)
	if interaction != nil {
		// If we have previous interactions, get them and process them.
		interactions, ok := interaction.Value().([]*server.Interaction)
		if !ok {
			c.requests.Set(id, data, c.eviction)
			return
		}
		matched := false
		for _, interaction := range interactions {
			if c.processInteractionForRequest(interaction, data) {
				matched = true
				break
			}
		}
		if matched {
			c.interactions.Delete(id)
		}
	} else {
		c.requests.Set(id, data, c.eviction)
	}
}

// HasMatchers returns true if an operator has interactsh part
// matchers or extractors.
//
// Used by requests to show result or not depending on presence of interact.sh
// data part matchers.
func HasMatchers(op *operators.Operators) bool {
	if op == nil {
		return false
	}

	for _, matcher := range op.Matchers {
		for _, dsl := range matcher.DSL {
			if strings.Contains(dsl, "interactsh") {
				return true
			}
		}
		if strings.HasPrefix(matcher.Part, "interactsh") {
			return true
		}
	}
	for _, matcher := range op.Extractors {
		if strings.HasPrefix(matcher.Part, "interactsh") {
			return true
		}
	}
	return false
}
