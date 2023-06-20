package engine

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
)

// Page is a single page in an isolated browser instance
type Page struct {
	input          *contextargs.Context
	options        *Options
	page           *rod.Page
	rules          []rule
	instance       *Instance
	hijackRouter   *rod.HijackRouter
	hijackNative   *Hijack
	mutex          *sync.RWMutex
	History        []HistoryData
	InteractshURLs []string
	payloads       map[string]interface{}
}

// HistoryData contains the page request/response pairs
type HistoryData struct {
	RawRequest  string
	RawResponse string
}

// Options contains additional configuration options for the browser instance
type Options struct {
	Timeout     time.Duration
	CookieReuse bool
}

// Run runs a list of actions by creating a new page in the browser.
func (i *Instance) Run(input *contextargs.Context, actions []*Action, payloads map[string]interface{}, options *Options) (map[string]string, *Page, error) {
	page, err := i.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, nil, err
	}
	page = page.Timeout(options.Timeout)

	if i.browser.customAgent != "" {
		if userAgentErr := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: i.browser.customAgent}); userAgentErr != nil {
			return nil, nil, userAgentErr
		}
	}

	createdPage := &Page{
		options:  options,
		page:     page,
		input:    input,
		instance: i,
		mutex:    &sync.RWMutex{},
		payloads: payloads,
	}

	// in case the page has request/response modification rules - enable global hijacking
	if createdPage.hasModificationRules() || containsModificationActions(actions...) {
		hijackRouter := page.HijackRequests()
		if err := hijackRouter.Add("*", "", createdPage.routingRuleHandler); err != nil {
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

	if _, err := page.SetExtraHeaders([]string{"Accept-Language", "en, en-GB, en-us;"}); err != nil {
		return nil, nil, err
	}

	// inject cookies
	// each http request is performed via the native go http client
	// we first inject the shared cookies
	URL, err := url.Parse(input.MetaInput.Input)
	if err != nil {
		return nil, nil, err
	}

	if cookies := input.CookieJar.Cookies(URL); options.CookieReuse && len(cookies) > 0 {
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
			param.URL = input.MetaInput.Input
		}
		err := page.SetCookies(params)
		if err != nil {
			return nil, nil, err
		}
	}

	// todo: this is wrong as the next intercepted result event might not be the result of page.Navigate
	//FIXME: this is a hack, make sure to fix this in the future. See: https://github.com/go-rod/rod/issues/188
	// var e proto.NetworkResponseReceived
	// wait := page.WaitEvent(&e)

	data, err := createdPage.ExecuteActions(input, actions)
	if err != nil {
		return nil, nil, err
	}

	// at the end of actions pull out updated cookies from the browser and inject them into the shared cookie jar
	if cookies, err := page.Cookies([]string{URL.String()}); options.CookieReuse && err == nil && len(cookies) > 0 {
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
		input.CookieJar.SetCookies(URL, httpCookies)
	}

	// todo: this is wrong as per previous comment - this info must be captured and filled from within createdPage.ExecuteActions with optimistic match based on URL
	// wait()
	// data["header"] = headersToString(e.Response.Headers)
	// data["status_code"] = fmt.Sprint(e.Response.Status)

	return data, createdPage, nil
}

// Close closes a browser page
func (p *Page) Close() {
	if p.hijackRouter != nil {
		_ = p.hijackRouter.Stop()
	}
	if p.hijackNative != nil {
		_ = p.hijackNative.Stop()
	}
	p.page.Close()
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

func (p *Page) hasModificationRules() bool {
	for _, rule := range p.rules {
		if containsAnyModificationActionType(rule.Action) {
			return true
		}
	}
	return false
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

// headersToString converts network headers to string
// func headersToString(headers proto.NetworkHeaders) string {
// 	builder := &strings.Builder{}
// 	for header, value := range headers {
// 		builder.WriteString(header)
// 		builder.WriteString(": ")
// 		builder.WriteString(value.String())
// 		builder.WriteRune('\n')
// 	}
// 	return builder.String()
// }

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
