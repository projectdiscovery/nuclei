package engine

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// Page is a single page in an isolated browser instance
type Page struct {
	page           *rod.Page
	rules          []requestRule
	instance       *Instance
	router         *rod.HijackRouter
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

// Run runs a list of actions by creating a new page in the browser.
func (i *Instance) Run(baseURL *url.URL, actions []*Action, payloads map[string]interface{}, timeout time.Duration) (map[string]string, *Page, error) {
	page, err := i.engine.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, nil, err
	}
	page = page.Timeout(timeout)

	if i.browser.customAgent != "" {
		if userAgentErr := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: i.browser.customAgent}); userAgentErr != nil {
			return nil, nil, userAgentErr
		}
	}

	createdPage := &Page{page: page, instance: i, mutex: &sync.RWMutex{}, payloads: payloads}
	router := page.HijackRequests()
	if routerErr := router.Add("*", "", createdPage.routingRuleHandler); routerErr != nil {
		return nil, nil, routerErr
	}
	createdPage.router = router

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

	go router.Run()
	data, err := createdPage.ExecuteActions(baseURL, actions)
	if err != nil {
		return nil, nil, err
	}
	return data, createdPage, nil
}

// Close closes a browser page
func (p *Page) Close() {
	_ = p.router.Stop()
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
