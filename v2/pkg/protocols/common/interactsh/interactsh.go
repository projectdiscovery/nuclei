package interactsh

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/karlseguin/ccache"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
)

// Client is a wrapped client for interactsh server.
type Client struct {
	// interactsh is a client for interactsh server.
	interactsh *client.Client
	// requests is a stored cache for interactsh-url->request-event data.
	requests *ccache.Cache

	dotHostname      string
	eviction         time.Duration
	pollDuration     time.Duration
	cooldownDuration time.Duration
}

// Options contains configuration options for interactsh nuclei integration.
type Options struct {
	// ServerURL is the URL of the interactsh server.
	ServerURL string
	// CacheSize is the numbers of requests to keep track of at a time.
	// Older items are discarded in LRU manner in favour of new requests.
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
	// Progress is the nuclei progress bar implementation.
	Progress *progress.Progress
}

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

	client := &Client{
		interactsh:       interactsh,
		eviction:         options.Eviction,
		dotHostname:      "." + parsed.Host,
		requests:         cache,
		pollDuration:     options.PollDuration,
		cooldownDuration: options.ColldownPeriod,
	}
	client.interactsh.StartPolling(client.pollDuration, func(interaction *server.Interaction) {
		item := client.requests.Get(interaction.UniqueID)
		fmt.Printf("got interaction: %v %v\n", interaction.UniqueID, item)
		if item == nil {
			return
		}
		data, ok := item.Value().(*internalRequestEvent)
		if !ok {
			return
		}
		client.requests.Delete(interaction.UniqueID)

		data.event.OperatorsResult = &operators.Result{
			Matches: map[string]struct{}{strings.ToLower(interaction.Protocol): {}},
		}
		data.event.Results = data.makeResultFunc(data.event)
		for _, result := range data.event.Results {
			result.Interaction = interaction
			options.Output.Write(result)
			options.Progress.IncrementMatched()
		}
	})
	return client, nil
}

// URL returns a new URL that can be interacted with
func (c *Client) URL() string {
	return c.interactsh.URL()
}

// Close closes the interactsh clients after waiting for cooldown period.
func (c *Client) Close() {
	if c.cooldownDuration > 0 {
		time.Sleep(c.cooldownDuration)
	}
	c.interactsh.StopPolling()
	c.interactsh.Close()
}

// MakeResultEventFunc is a result making function for nuclei
type MakeResultEventFunc func(wrapped *output.InternalWrappedEvent) []*output.ResultEvent

type internalRequestEvent struct {
	makeResultFunc MakeResultEventFunc
	event          *output.InternalWrappedEvent
}

// RequestEvent is the event for a network request sent by nuclei.
func (c *Client) RequestEvent(interactshURL string, event *output.InternalWrappedEvent, makeResult MakeResultEventFunc) {
	id := strings.TrimSuffix(interactshURL, c.dotHostname)
	c.requests.Set(id, &internalRequestEvent{makeResultFunc: makeResult, event: event}, c.eviction)
}
