package engine

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	httputil "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
	urlutil "github.com/projectdiscovery/utils/url"
)

// Page is a single page in an isolated browser instance
type Page struct {
	ctx                *contextargs.Context
	inputURL           *urlutil.URL
	options            *Options
	page               *rod.Page
	rules              []rule
	instance           *Instance
	hijackRouter       *rod.HijackRouter
	hijackNative       *Hijack
	mutex              *sync.RWMutex
	History            []HistoryData
	InteractshURLs     []string
	ActionDurations    []time.Duration
	payloads           map[string]interface{}
	variables          map[string]interface{}
	lastActionNavigate *Action
	cancel             context.CancelFunc
}

// HistoryData contains the page request/response pairs
type HistoryData struct {
	RawRequest  string
	RawResponse string
}

// Options contains additional configuration options for the browser instance
type Options struct {
	Timeout       time.Duration
	DisableCookie bool
	Options       *types.Options
	// OnNavigationResponse receives the response to the initial URL once the
	// actions ran, even when they failed: the browser fails a navigation on
	// an error status with an empty body, and that status still matters.
	OnNavigationResponse func(*http.Response)
}

// Run runs a list of actions by creating a new page in the browser.
func (i *Instance) Run(ctx *contextargs.Context, actions []*Action, payloads map[string]interface{}, options *Options) (ActionData, *Page, error) {
	if err := ctx.Context().Err(); err != nil {
		return nil, nil, err
	}

	pageContext := ctx.Context()
	cancelPage := func() {}
	if options.Timeout > 0 {
		pageContext, cancelPage = context.WithTimeout(pageContext, options.Timeout)
	}
	page, err := i.engine.Context(pageContext).Page(proto.TargetCreateTarget{})
	if err != nil {
		cancelPage()
		return nil, nil, err
	}
	page = page.Context(pageContext)
	createdPage := &Page{
		options:  options,
		page:     page,
		ctx:      ctx,
		instance: i,
		mutex:    &sync.RWMutex{},
		cancel:   cancelPage,
	}
	successfulPageCreation := false
	defer func() {
		if !successfulPageCreation {
			createdPage.Close()
		}
	}()

	if err = i.browser.applyDefaultHeaders(page); err != nil {
		return nil, nil, err
	}

	if i.browser.customAgent != "" {
		if userAgentErr := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: i.browser.customAgent}); userAgentErr != nil {
			return nil, nil, userAgentErr
		}
	}

	payloads = generators.MergeMaps(payloads,
		generators.BuildPayloadFromOptions(i.browser.options),
	)

	target := ctx.MetaInput.Input
	input, err := urlutil.Parse(target)
	if err != nil {
		return nil, nil, errkit.Wrapf(err, "could not parse URL %s", target)
	}

	hasTrailingSlash := httputil.HasTrailingSlash(target)
	variables := utils.GenerateVariables(input, hasTrailingSlash, contextargs.GenerateVariables(ctx))
	variables = generators.MergeMaps(variables, payloads)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("Headless Protocol request variables: %s\n", vardump.DumpVariables(variables))
	}

	createdPage.payloads = payloads
	createdPage.variables = variables
	createdPage.inputURL = input

	if options != nil && options.Options != nil {
		if netErr := protocolstate.SetupHeadlessNetworkPolicy(options.Options, page); netErr != nil {
			return nil, nil, netErr
		}
	}

	httpclient, err := i.browser.getHTTPClient()
	if err != nil {
		return nil, nil, err
	}

	// in case the page has request/response modification rules - enable global hijacking
	if createdPage.hasModificationRules() || containsModificationActions(actions...) {
		hijackRouter := page.HijackRequests()
		if err := hijackRouter.Add("*", "", createdPage.routingRuleHandler(httpclient)); err != nil {
			return nil, nil, err
		}
		createdPage.hijackRouter = hijackRouter
		go hijackRouter.Run()
	} else {
		hijackRouter := NewHijack(page)
		hijackRouter.SetPattern(&proto.FetchRequestPattern{
			URLPattern:   "*",
			RequestStage: proto.FetchRequestStageResponse,
		})
		createdPage.hijackNative = hijackRouter
		hijackRouterHandler := hijackRouter.Start(createdPage.routingRuleHandlerNative)
		go func() {
			_ = hijackRouterHandler()
		}()
	}

	if err := page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{Viewport: &proto.PageViewport{
		Scale:  1,
		Width:  float64(1920),
		Height: float64(1080),
	}}); err != nil {
		return nil, nil, err
	}

	// inject cookies
	// each http request is performed via the native go http client
	// we first inject the shared cookies
	URL, err := url.Parse(ctx.MetaInput.Input)
	if err != nil {
		return nil, nil, err
	}

	if !options.DisableCookie {
		if cookies := ctx.CookieJar.Cookies(URL); len(cookies) > 0 {
			var NetworkCookies []*proto.NetworkCookie
			for _, cookie := range cookies {
				networkCookie := &proto.NetworkCookie{
					Name:     cookie.Name,
					Value:    cookie.Value,
					Domain:   cookie.Domain,
					Path:     cookie.Path,
					HTTPOnly: cookie.HttpOnly,
					Secure:   cookie.Secure,
					Expires:  proto.TimeSinceEpoch(cookie.Expires.Unix()),
					SameSite: proto.NetworkCookieSameSite(GetSameSite(cookie)),
					Priority: proto.NetworkCookiePriorityLow,
				}
				NetworkCookies = append(NetworkCookies, networkCookie)
			}
			params := proto.CookiesToParams(NetworkCookies)
			for _, param := range params {
				param.URL = ctx.MetaInput.Input
			}
			err := page.SetCookies(params)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	data, err := createdPage.ExecuteActions(ctx, actions)
	if options.OnNavigationResponse != nil {
		if resp := createdPage.NavigationResponse(); resp != nil {
			options.OnNavigationResponse(resp)
		}
	}
	if err != nil {
		return nil, nil, err
	}

	if !options.DisableCookie {
		// at the end of actions pull out updated cookies from the browser and inject them into the shared cookie jar
		if cookies, err := page.Cookies([]string{URL.String()}); !options.DisableCookie && err == nil && len(cookies) > 0 {
			var httpCookies []*http.Cookie
			for _, cookie := range cookies {
				httpCookie := &http.Cookie{
					Name:     cookie.Name,
					Value:    cookie.Value,
					Domain:   cookie.Domain,
					Path:     cookie.Path,
					HttpOnly: cookie.HTTPOnly,
					Secure:   cookie.Secure,
				}
				httpCookies = append(httpCookies, httpCookie)
			}
			ctx.CookieJar.SetCookies(URL, httpCookies)
		}
	}

	if resp := createdPage.FirstResponse(); resp != nil {
		data["header"] = utils.HeadersToString(resp.Header)
		data["status_code"] = fmt.Sprint(resp.StatusCode)
	}

	successfulPageCreation = true // avoid closing the page in case of success in deferred function
	return data, createdPage, nil
}

// Close closes a browser page
func (p *Page) Close() {
	cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), browserCleanupTimeout)
	defer cancelCleanup()
	p.close(cleanupCtx)
}

func (p *Page) close(cleanupCtx context.Context) {
	if p.hijackRouter != nil {
		_ = p.hijackRouter.Stop()
	}
	if p.hijackNative != nil {
		_ = p.hijackNative.Stop()
	}
	if p.page.GetContext().Err() != nil {
		_, _ = proto.TargetCloseTarget{TargetID: p.page.TargetID}.Call(p.page.Browser().Context(cleanupCtx))
	} else {
		_ = p.page.Context(cleanupCtx).Close()
	}
	if p.cancel != nil {
		p.cancel()
	}
}

// Page returns the current page for the actions
func (p *Page) Page() *rod.Page {
	return p.page
}

// Browser returns the browser that created the current page
func (p *Page) Browser() *rod.Browser {
	return p.instance.engine
}

// URL returns the URL for the current page.
func (p *Page) URL() string {
	info, err := p.page.Info()
	if err != nil {
		return ""
	}
	return info.URL
}

// FirstResponse returns the response to the very first request from the
// browser, which is assumed to be the one for the initial URL. It is nil when
// none was recorded.
func (p *Page) FirstResponse() *http.Response {
	p.mutex.RLock()
	if len(p.History) == 0 {
		p.mutex.RUnlock()
		return nil
	}
	raw := p.History[0].RawResponse
	p.mutex.RUnlock()
	return parseHistoryResponse(raw)
}

// NavigationResponse returns the response that ended the initial navigation,
// nil when none was recorded. Redirect hops are separate history items, so it
// follows Location from the first item to the response that was not a redirect.
func (p *Page) NavigationResponse() *http.Response {
	p.mutex.RLock()
	history := slices.Clone(p.History)
	p.mutex.RUnlock()
	return navigationResponse(history)
}

// maxNavigationRedirects matches the redirect limit of Chromium.
const maxNavigationRedirects = 20

func navigationResponse(history []HistoryData) *http.Response {
	if len(history) == 0 {
		return nil
	}
	resp := parseHistoryResponse(history[0].RawResponse)
	current := historyRequestURL(history[0].RawRequest)
	next := 1
	for hop := 0; resp != nil && current != nil && hop < maxNavigationRedirects; hop++ {
		if resp.StatusCode < 300 || resp.StatusCode > 399 {
			break
		}
		location := resp.Header.Get("Location")
		if location == "" {
			break
		}
		target, err := current.Parse(location)
		if err != nil {
			break
		}
		found := false
		for i := next; i < len(history); i++ {
			candidate := historyRequestURL(history[i].RawRequest)
			if candidate == nil || !sameResource(candidate, target) {
				continue
			}
			hopResp := parseHistoryResponse(history[i].RawResponse)
			if hopResp == nil {
				break
			}
			resp, current, next, found = hopResp, candidate, i+1, true
			break
		}
		if !found {
			break
		}
	}
	return resp
}

func parseHistoryResponse(raw string) *http.Response {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()
	return resp
}

// historyRequestURL reads the target of a recorded request. The native hijack
// records an absolute URL on the request line. The rod router records a path
// and a Host header.
func historyRequestURL(raw string) *url.URL {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return nil
	}
	target, err := url.Parse(fields[1])
	if err != nil {
		return nil
	}
	if target.Host != "" {
		return target
	}
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Host") {
			target.Host = strings.TrimSpace(value)
			return target
		}
	}
	return nil
}

// sameResource ignores the scheme, so an http to https redirect still matches
// when the recorded request has no scheme.
func sameResource(a, b *url.URL) bool {
	pathOf := func(u *url.URL) string {
		if u.EscapedPath() == "" {
			return "/"
		}
		return u.EscapedPath()
	}
	return strings.EqualFold(a.Host, b.Host) && pathOf(a) == pathOf(b) && a.RawQuery == b.RawQuery
}

// DumpHistory returns the full page navigation history
func (p *Page) DumpHistory() string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var historyDump strings.Builder
	for _, historyData := range p.History {
		historyDump.WriteString(historyData.RawRequest)
		historyDump.WriteString(historyData.RawResponse)
	}
	return historyDump.String()
}

// addToHistory adds a request/response pair to the page history
func (p *Page) addToHistory(historyData ...HistoryData) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.History = append(p.History, historyData...)
}

func (p *Page) addInteractshURL(URLs ...string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.InteractshURLs = append(p.InteractshURLs, URLs...)
}

// appendRule records a request/response modification rule. The hijack handler
// reads p.rules from a separate goroutine, so writes must be synchronized.
func (p *Page) appendRule(r rule) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.rules = append(p.rules, r)
}

// rulesSnapshot returns a copy of the current rules for lock-free iteration by
// the hijack handler (which performs network I/O and must not hold the lock).
func (p *Page) rulesSnapshot() []rule {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return slices.Clone(p.rules)
}

func (p *Page) hasModificationRules() bool {
	for _, rule := range p.rulesSnapshot() {
		if containsAnyModificationActionType(rule.Action) {
			return true
		}
	}
	return false
}

// updateLastNavigatedURL updates the last navigated URL in the instance's
// request log.
func (p *Page) updateLastNavigatedURL() {
	if p.lastActionNavigate == nil {
		return
	}

	templateURL := p.lastActionNavigate.GetArg("url")
	p.instance.requestLog[templateURL] = p.URL()
}

func containsModificationActions(actions ...*Action) bool {
	for _, action := range actions {
		if containsAnyModificationActionType(action.ActionType.ActionType) {
			return true
		}
	}
	return false
}

func containsAnyModificationActionType(actionTypes ...ActionType) bool {
	for _, actionType := range actionTypes {
		switch actionType {
		case ActionSetMethod:
			return true
		case ActionAddHeader:
			return true
		case ActionSetHeader:
			return true
		case ActionDeleteHeader:
			return true
		case ActionSetBody:
			return true
		}
	}
	return false
}

func GetSameSite(cookie *http.Cookie) string {
	switch cookie.SameSite {
	case http.SameSiteNoneMode:
		return "none"
	case http.SameSiteLaxMode:
		return "lax"
	case http.SameSiteStrictMode:
		return "strict"
	case http.SameSiteDefaultMode:
		fallthrough
	default:
		return ""
	}
}
