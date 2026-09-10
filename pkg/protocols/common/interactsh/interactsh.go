package interactsh

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"errors"

	"github.com/projectdiscovery/gcache"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/frequency"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/writer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Client is a wrapped client for interactsh server.
type Client struct {
	sync.Once
	sync.RWMutex
	cacheOnce          sync.Once
	requestLifecycleMu sync.RWMutex

	options *Options

	// interactsh is a client for interactsh server.
	interactsh *client.Client
	// requests is a stored cache for interactsh-url->request-event data.
	requests gcache.Cache[string, *RequestData]
	// interactions is a stored cache for interactsh-interaction->interactsh-url data
	interactions gcache.Cache[string, []*server.Interaction]
	// matchedTemplates is a stored cache to track matched templates
	matchedTemplates gcache.Cache[string, bool]
	// interactshURLs is a stored cache to track multiple interactsh markers
	interactshURLs gcache.Cache[string, string]

	eviction         time.Duration
	pollDuration     time.Duration
	cooldownDuration time.Duration

	hostname string

	// determines if wait the cooldown period in case of generated URL
	generated atomic.Bool
	matched   atomic.Bool
}

// RequestScope owns the delayed interaction registrations created by one
// engine execution. A shared Client can serve many concurrent executions, but
// each execution still needs its own callback window and deterministic cleanup.
type RequestScope struct {
	client    *Client
	once      sync.Once
	mu        sync.Mutex
	ids       map[string]struct{}
	closing   bool
	callbacks sync.WaitGroup
}

// NewRequestScope creates an execution-scoped interaction lifecycle. Call
// Close after the execution work pool has drained.
func (c *Client) NewRequestScope() *RequestScope {
	return &RequestScope{client: c, ids: make(map[string]struct{})}
}

func (s *RequestScope) track(id string) {
	if s == nil || id == "" {
		return
	}
	s.mu.Lock()
	if !s.closing {
		s.ids[id] = struct{}{}
	}
	s.mu.Unlock()
}

func (s *RequestScope) beginCallback() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.callbacks.Add(1)
	return true
}

func (s *RequestScope) endCallback() {
	if s != nil {
		s.callbacks.Done()
	}
}

// Close waits the same callback cooldown used by a standalone Client, then
// removes only this execution's unmatched registrations. The shared poller and
// registrations belonging to other executions remain active.
func (s *RequestScope) Close() {
	if s == nil || s.client == nil {
		return
	}
	s.once.Do(func() {
		s.mu.Lock()
		hasRegistrations := len(s.ids) > 0
		s.mu.Unlock()
		if hasRegistrations && s.client.cooldownDuration > 0 {
			time.Sleep(s.client.cooldownDuration)
		}

		// Serialize registration removal with the poller's request lookup and
		// callback admission. A callback that already found this execution's
		// request is counted before closing begins; a later callback cannot start.
		s.client.requestLifecycleMu.Lock()
		s.mu.Lock()
		s.closing = true
		ids := make([]string, 0, len(s.ids))
		for id := range s.ids {
			ids = append(ids, id)
		}
		s.mu.Unlock()
		if s.client.requests != nil {
			for _, id := range ids {
				s.client.requests.Remove(id)
			}
		}
		s.client.requestLifecycleMu.Unlock()

		// Result writers, progress reporters, and issue clients remain owned by
		// the execution until every callback admitted above has completed.
		s.callbacks.Wait()
	})
}

// New returns a new interactsh server client
func New(options *Options) (*Client, error) {
	interactClient := &Client{
		eviction:         options.Eviction,
		options:          options,
		pollDuration:     options.PollDuration,
		cooldownDuration: options.CooldownPeriod,
	}
	return interactClient, nil
}

func (c *Client) initializeCaches() {
	c.cacheOnce.Do(func() {
		requests := gcache.New[string, *RequestData](c.options.CacheSize).LRU().Build()
		interactions := gcache.New[string, []*server.Interaction](defaultMaxInteractionsCount).LRU().Build()
		matchedTemplates := gcache.New[string, bool](defaultMaxInteractionsCount).LRU().Build()
		interactshURLs := gcache.New[string, string](defaultMaxInteractionsCount).LRU().Build()

		c.interactions = interactions
		c.matchedTemplates = matchedTemplates
		c.interactshURLs = interactshURLs
		c.requests = requests
	})
}

func (c *Client) poll() error {
	if c.options.NoInteractsh {
		// do not init if disabled
		return ErrInteractshClientNotInitialized
	}
	c.initializeCaches()
	interactsh, err := client.New(&client.Options{
		ServerURL:           c.options.ServerURL,
		Token:               c.options.Authorization,
		DisableHTTPFallback: c.options.DisableHttpFallback,
		HTTPClient:          c.options.HTTPClient,
		KeepAliveInterval:   time.Minute,
	})
	if err != nil {
		return errkit.Wrap(err, "could not create client")
	}

	c.interactsh = interactsh

	interactURL := interactsh.URL()
	interactDomain := interactURL[strings.Index(interactURL, ".")+1:]
	gologger.Info().Msgf("Using Interactsh Server: %s", interactDomain)

	c.setHostname(interactDomain)

	err = interactsh.StartPolling(c.pollDuration, func(interaction *server.Interaction) {
		c.requestLifecycleMu.RLock()
		request, err := c.requests.Get(interaction.UniqueID)
		callbackAdmitted := request != nil && request.Scope.beginCallback()
		c.requestLifecycleMu.RUnlock()
		// for more context in github actions
		if strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") && c.options.Debug {
			gologger.DefaultLogger.Print().Msgf("[Interactsh]: got interaction of %v for request %v and error %v", interaction, request, err)
		}
		if errors.Is(err, gcache.KeyNotFoundError) || request == nil {
			// If we don't have any request for this ID, add it to temporary
			// lru cache, so we can correlate when we get an add request.
			items, err := c.interactions.Get(interaction.UniqueID)
			if errkit.Is(err, gcache.KeyNotFoundError) || items == nil {
				_ = c.interactions.SetWithExpire(interaction.UniqueID, []*server.Interaction{interaction}, defaultInteractionDuration)
			} else {
				items = append(items, interaction)
				_ = c.interactions.SetWithExpire(interaction.UniqueID, items, defaultInteractionDuration)
			}
			return
		}
		if !callbackAdmitted {
			return
		}
		defer request.Scope.endCallback()

		if requestShouldStopAtFirstMatch(request) || c.options.StopAtFirstMatch {
			if gotItem, err := c.matchedTemplates.Get(eventHash(request.Event)); gotItem && err == nil {
				return
			}
		}

		_ = c.processInteractionForRequest(interaction, request)
	})

	if err != nil {
		return errkit.Wrap(err, "could not perform interactsh polling")
	}
	return nil
}

// requestShouldStopAtFirstmatch checks if further interactions should be stopped
// note: extra care should be taken while using this function since internalEvent is
// synchronized all the time and if caller functions has already acquired lock its best to explicitly specify that
// we could use `TryLock()` but that may over complicate things and need to differentiate
// situations whether to block or skip
func requestShouldStopAtFirstMatch(request *RequestData) bool {
	request.Event.RLock()
	defer request.Event.RUnlock()

	if stop, ok := request.Event.InternalEvent[stopAtFirstMatchAttribute]; ok {
		if v, ok := stop.(bool); ok {
			return v
		}
	}
	return false
}

// processInteractionForRequest processes an interaction for a request
func (c *Client) processInteractionForRequest(interaction *server.Interaction, data *RequestData) bool {
	var result *operators.Result
	var matched bool
	var templateID string
	data.Event.Lock()
	data.Event.InternalEvent["interactsh_protocol"] = interaction.Protocol
	if strings.EqualFold(interaction.Protocol, "dns") {
		data.Event.InternalEvent["interactsh_request"] = strings.ToLower(interaction.RawRequest)
	} else {
		data.Event.InternalEvent["interactsh_request"] = interaction.RawRequest
	}
	data.Event.InternalEvent["interactsh_response"] = interaction.RawResponse
	data.Event.InternalEvent["interactsh_ip"] = interaction.RemoteAddress
	if data.Operators != nil {
		result, matched = data.Operators.Execute(data.Event.InternalEvent, data.MatchFunc, data.ExtractFunc, c.options.Debug || c.options.DebugRequest || c.options.DebugResponse)
	} else {
		// this is most likely a bug so error instead of warning
		if data.Event.InternalEvent != nil {
			templateID = fmt.Sprint(data.Event.InternalEvent[templateIdAttribute])
		}
	}
	data.Event.Unlock()
	if data.Operators == nil {
		gologger.Error().Msgf("missing compiled operators for '%v' template", templateID)
	}

	// for more context in github actions
	if strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") && c.options.Debug {
		gologger.DefaultLogger.Print().Msgf("[Interactsh]: got result %v and status %v after processing interaction", result, matched)
	}

	fuzzParamsFrequency := data.FuzzParamsFrequency
	if fuzzParamsFrequency == nil {
		fuzzParamsFrequency = c.options.FuzzParamsFrequency
	}
	if fuzzParamsFrequency != nil {
		if !matched {
			fuzzParamsFrequency.MarkParameter(data.Parameter, data.Request.String(), data.Operators.TemplateID)
		} else {
			fuzzParamsFrequency.UnmarkParameter(data.Parameter, data.Request.String(), data.Operators.TemplateID)
		}
	}

	// if we don't match, return
	if !matched || result == nil {
		return false
	}
	c.requests.Remove(interaction.UniqueID)

	if data.Event.OperatorsResult != nil {
		data.Event.OperatorsResult.Merge(result)
	} else {
		data.Event.SetOperatorResult(result)
	}
	// ensure payload values are preserved for interactsh-only matches
	data.Event.Lock()
	if data.Event.OperatorsResult != nil && len(data.Event.OperatorsResult.PayloadValues) == 0 {
		if payloads, ok := data.Event.InternalEvent["payloads"].(map[string]interface{}); ok {
			data.Event.OperatorsResult.PayloadValues = payloads
		}
	}
	data.Event.Unlock()

	data.Event.Lock()
	data.Event.Results = data.MakeResultFunc(data.Event)
	for _, event := range data.Event.Results {
		event.Interaction = interaction
	}
	data.Event.Unlock()

	if c.options.Debug || c.options.DebugRequest || c.options.DebugResponse {
		c.debugPrintInteraction(interaction, data.Event.OperatorsResult)
	}

	// if event is not already matched, write it to output
	outputWriter := data.Output
	if outputWriter == nil {
		outputWriter = c.options.Output
	}
	progressClient := data.Progress
	if progressClient == nil {
		progressClient = c.options.Progress
	}
	issuesClient := data.IssuesClient
	if issuesClient == nil {
		issuesClient = c.options.IssuesClient
	}
	if !data.Event.InteractshMatched.Load() && writer.WriteResult(data.Event, outputWriter, progressClient, issuesClient) {
		data.Event.InteractshMatched.Store(true)
		c.matched.Store(true)
		if requestShouldStopAtFirstMatch(data) || c.options.StopAtFirstMatch {
			_ = c.matchedTemplates.SetWithExpire(eventHash(data.Event), true, defaultInteractionDuration)
		}
	}

	return true
}

func (c *Client) AlreadyMatched(data *RequestData) bool {
	c.initializeCaches()
	return c.matchedTemplates.Has(eventHash(data.Event))
}

// URL returns a new URL that can be interacted with
func (c *Client) URL() (string, error) {
	// first time initialization
	var err error
	c.Do(func() {
		err = c.poll()
	})
	if err != nil {
		return "", errkit.Wrap(ErrInteractshClientNotInitialized, err.Error())
	}

	if c.interactsh == nil {
		return "", ErrInteractshClientNotInitialized
	}

	c.generated.Store(true)
	return c.interactsh.URL(), nil
}

// Close the interactsh clients after waiting for cooldown period.
func (c *Client) Close() bool {
	if c.cooldownDuration > 0 && c.generated.Load() {
		time.Sleep(c.cooldownDuration)
	}
	if c.interactsh != nil {
		_ = c.interactsh.StopPolling()
		_ = c.interactsh.Close()
	}

	if c.requests != nil {
		c.requests.Purge()
		c.interactions.Purge()
		c.matchedTemplates.Purge()
		c.interactshURLs.Purge()
	}

	return c.matched.Load()
}

// Replace replaces the default Interactsh URL placeholders with interactsh URLs.
func (c *Client) Replace(data string, interactshURLs []string) (string, []string) {
	for _, interactshURLMarker := range marker.FindInteractshURLMarkers(data) {
		if url, err := c.NewURLWithData(interactshURLMarker); err == nil {
			interactshURLs = append(interactshURLs, url)
			data = strings.Replace(data, interactshURLMarker, url, 1)
		}
	}
	return data, interactshURLs
}

// ReplaceWithMarker replaces custom regex matches with Interactsh URLs and appends them to interactshURLs.
func (c *Client) ReplaceWithMarker(data string, regex *regexp.Regexp, interactshURLs []string) (string, []string) {
	for _, interactshURLMarker := range regex.FindAllString(data, -1) {
		if url, err := c.NewURLWithData(interactshURLMarker); err == nil {
			interactshURLs = append(interactshURLs, url)
			data = strings.Replace(data, interactshURLMarker, url, 1)
		}
	}
	return data, interactshURLs
}

func (c *Client) NewURL() (string, error) {
	return c.NewURLWithData("")
}

func (c *Client) NewURLWithData(data string) (string, error) {
	url, err := c.URL()
	if err != nil {
		return "", err
	}
	if url == "" {
		return "", errors.New("empty interactsh url")
	}
	_ = c.interactshURLs.SetWithExpire(url, data, defaultInteractionDuration)
	return url, nil
}

// MakePlaceholders does placeholders for interact URLs and other data to a map
func (c *Client) MakePlaceholders(urls []string, data map[string]interface{}) {
	data["interactsh-server"] = c.getHostname()
	if len(urls) == 0 {
		return
	}
	c.initializeCaches()
	for _, url := range urls {
		if interactshURLMarker, err := c.interactshURLs.Get(url); interactshURLMarker != "" && err == nil {
			interactshMarker := strings.TrimSuffix(strings.TrimPrefix(interactshURLMarker, "{{"), "}}")

			c.interactshURLs.Remove(url)

			data[interactshMarker] = url
			urlIndex := strings.Index(url, ".")
			if urlIndex == -1 {
				continue
			}
			data[strings.Replace(interactshMarker, "url", "id", 1)] = url[:urlIndex]
		}
	}
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

	Parameter string
	Request   *retryablehttp.Request

	// These fields route delayed results back to the execution that registered
	// the request when the Interactsh client is shared concurrently.
	Output              output.Writer
	Progress            progress.Progress
	IssuesClient        reporting.Client
	FuzzParamsFrequency *frequency.Tracker
	Scope               *RequestScope
}

// RequestEvent is the event for a network request sent by nuclei.
func (c *Client) RequestEvent(interactshURLs []string, data *RequestData) {
	if len(interactshURLs) == 0 {
		return
	}
	c.initializeCaches()
	for _, interactshURL := range interactshURLs {
		id := strings.TrimRight(strings.TrimSuffix(interactshURL, c.getHostname()), ".")
		data.Scope.track(id)

		if requestShouldStopAtFirstMatch(data) || c.options.StopAtFirstMatch {
			gotItem, err := c.matchedTemplates.Get(eventHash(data.Event))
			if gotItem && err == nil {
				break
			}
		}

		interactions, err := c.interactions.Get(id)
		if interactions != nil && err == nil {
			for _, interaction := range interactions {
				if !data.Scope.beginCallback() {
					break
				}
				matched := c.processInteractionForRequest(interaction, data)
				data.Scope.endCallback()
				if matched {
					c.interactions.Remove(id)
					break
				}
			}
		} else {
			_ = c.requests.SetWithExpire(id, data, c.eviction)
		}
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
			if stringsutil.ContainsAnyI(dsl, "interactsh") {
				return true
			}
		}
		if stringsutil.HasPrefixI(matcher.Part, "interactsh") {
			return true
		}
	}
	for _, matcher := range op.Extractors {
		if stringsutil.HasPrefixI(matcher.Part, "interactsh") {
			return true
		}
	}
	return false
}

// HasMarkers checks if the text contains interactsh markers
func HasMarkers(data string) bool {
	return marker.HasInteractshURLMarker(data)
}

func (c *Client) debugPrintInteraction(interaction *server.Interaction, event *operators.Result) {
	builder := &bytes.Buffer{}

	switch interaction.Protocol {
	case "dns":
		builder.WriteString(formatInteractionHeader("DNS", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug {
			builder.WriteString(formatInteractionMessage("DNS Request", interaction.RawRequest, event, c.options.NoColor))
		}
		if c.options.DebugResponse || c.options.Debug {
			builder.WriteString(formatInteractionMessage("DNS Response", interaction.RawResponse, event, c.options.NoColor))
		}
	case "http":
		builder.WriteString(formatInteractionHeader("HTTP", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug {
			builder.WriteString(formatInteractionMessage("HTTP Request", interaction.RawRequest, event, c.options.NoColor))
		}
		if c.options.DebugResponse || c.options.Debug {
			builder.WriteString(formatInteractionMessage("HTTP Response", interaction.RawResponse, event, c.options.NoColor))
		}
	case "smtp":
		builder.WriteString(formatInteractionHeader("SMTP", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug || c.options.DebugResponse {
			builder.WriteString(formatInteractionMessage("SMTP Interaction", interaction.RawRequest, event, c.options.NoColor))
		}
	case "ldap":
		builder.WriteString(formatInteractionHeader("LDAP", interaction.FullId, interaction.RemoteAddress, interaction.Timestamp))
		if c.options.DebugRequest || c.options.Debug || c.options.DebugResponse {
			builder.WriteString(formatInteractionMessage("LDAP Interaction", interaction.RawRequest, event, c.options.NoColor))
		}
	}
	_, _ = fmt.Fprint(os.Stderr, builder.String())
}

func formatInteractionHeader(protocol, ID, address string, at time.Time) string {
	return fmt.Sprintf("[%s] Received %s interaction from %s at %s", ID, protocol, address, at.Format("2006-01-02 15:04:05"))
}

func formatInteractionMessage(key, value string, event *operators.Result, noColor bool) string {
	value = responsehighlighter.Highlight(event, value, noColor, false)
	return fmt.Sprintf("\n------------\n%s\n------------\n\n%s\n\n", key, value)
}

func hash(internalEvent output.InternalEvent) string {
	templateId := internalEvent[templateIdAttribute].(string)
	host := internalEvent["host"].(string)
	return fmt.Sprintf("%s:%s", templateId, host)
}

func eventHash(event *output.InternalWrappedEvent) string {
	event.RLock()
	defer event.RUnlock()

	return hash(event.InternalEvent)
}

func (c *Client) getHostname() string {
	c.RLock()
	defer c.RUnlock()

	return c.hostname
}

func (c *Client) setHostname(hostname string) {
	c.Lock()
	defer c.Unlock()

	c.hostname = hostname
}

// GetHostname returns the configured interactsh server hostname.
func (c *Client) GetHostname() string {
	return c.getHostname()
}
