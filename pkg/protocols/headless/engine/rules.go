package engine

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// routingRuleHandler handles proxy rule for actions related to request/response modification
func (p *Page) routingRuleHandler(httpClient *http.Client) func(ctx *rod.Hijack) {
	return func(ctx *rod.Hijack) {
		// usually browsers don't use chunked transfer encoding, so we set the content-length nevertheless
		ctx.Request.Req().ContentLength = int64(len(ctx.Request.Body()))
		// snapshot the rules once: ExecuteActions may still be appending rules
		// from another goroutine while this hijack handler runs.
		rules := p.rulesSnapshot()
		for _, rule := range rules {
			if rule.Part != "request" {
				continue
			}

			switch rule.Action {
			case ActionSetMethod:
				rule.Do(func() {
					ctx.Request.Req().Method = rule.Args["method"]
				})
			case ActionAddHeader:
				ctx.Request.Req().Header.Add(rule.Args["key"], rule.Args["value"])
			case ActionSetHeader:
				ctx.Request.Req().Header.Set(rule.Args["key"], rule.Args["value"])
			case ActionDeleteHeader:
				ctx.Request.Req().Header.Del(rule.Args["key"])
			case ActionSetBody:
				body := rule.Args["body"]
				ctx.Request.Req().ContentLength = int64(len(body))
				ctx.Request.SetBody(body)
			}
		}

		// each http request is performed via the native go http client
		// we first inject the shared cookies
		reqURL := ctx.Request.URL()
		if !p.options.DisableCookie && p.ctx != nil && httpClient != nil {
			syncRequestCookies(p.ctx.CookieJar, httpClient.Jar, reqURL)
		}

		// perform the request
		if err := ctx.LoadResponse(httpClient, true); err != nil {
			gologger.Verbose().Msgf("headless: failed to load response for %s: %s", reqURL, err)
		}

		if !p.options.DisableCookie && p.ctx != nil && httpClient != nil {
			// retrieve the updated cookies from the native http client and inject them into the shared cookie jar
			// keeps existing one if not present
			syncResponseCookies(p.ctx.CookieJar, httpClient.Jar, reqURL)
		}

		for _, rule := range rules {
			if rule.Part != "response" {
				continue
			}

			switch rule.Action {
			case ActionAddHeader:
				ctx.Response.Headers().Add(rule.Args["key"], rule.Args["value"])
			case ActionSetHeader:
				ctx.Response.Headers().Set(rule.Args["key"], rule.Args["value"])
			case ActionDeleteHeader:
				ctx.Response.Headers().Del(rule.Args["key"])
			case ActionSetBody:
				body := rule.Args["body"]
				ctx.Response.Headers().Set("Content-Length", fmt.Sprintf("%d", len(body)))
				ctx.Response.SetBody(rule.Args["body"])
			}
		}

		// store history
		req := ctx.Request.Req()
		var rawReq string
		if raw, err := httputil.DumpRequestOut(req, true); err == nil {
			rawReq = string(raw)
		}

		// attempts to rebuild the response
		var rawResp strings.Builder
		respPayloads := ctx.Response.Payload()
		if respPayloads != nil {
			fmt.Fprintf(&rawResp, "HTTP/1.1 %d %s\n", respPayloads.ResponseCode, respPayloads.ResponsePhrase)
			for _, header := range respPayloads.ResponseHeaders {
				rawResp.WriteString(header.Name + ": " + header.Value + "\n")
			}
			rawResp.WriteString("\n")
			rawResp.WriteString(ctx.Response.Body())
		}

		// dump request
		historyData := HistoryData{
			RawRequest:  rawReq,
			RawResponse: rawResp.String(),
		}
		p.addToHistory(historyData)
	}
}

// routingRuleHandlerNative handles native proxy rule
func (p *Page) routingRuleHandlerNative(e *proto.FetchRequestPaused) error {
	// ValidateNFailRequest validates if Local file access is enabled
	// and local network access is enables if not it will fail the request
	// that don't match the rules
	if err := protocolstate.ValidateNFailRequest(p.options.Options, p.page, e); err != nil {
		return err
	}
	body, _ := FetchGetResponseBody(p.page, e)
	headers := make(map[string][]string)
	for _, h := range e.ResponseHeaders {
		headers[h.Name] = []string{h.Value}
	}

	var statusCode int
	if e.ResponseStatusCode != nil {
		statusCode = *e.ResponseStatusCode
	}

	// attempts to rebuild request
	var rawReq strings.Builder
	fmt.Fprintf(&rawReq, "%s %s %s\n", e.Request.Method, e.Request.URL, "HTTP/1.1")
	for _, header := range e.Request.Headers {
		fmt.Fprintf(&rawReq, "%s\n", header.String())
	}
	if e.Request.HasPostData {
		fmt.Fprintf(&rawReq, "\n%s\n", e.Request.PostData)
	}

	// attempts to rebuild the response
	var rawResp strings.Builder
	fmt.Fprintf(&rawResp, "HTTP/1.1 %d %s\n", statusCode, e.ResponseStatusText)
	for _, header := range e.ResponseHeaders {
		rawResp.WriteString(header.Name + ": " + header.Value + "\n")
	}
	rawResp.WriteString("\n")
	rawResp.Write(body)

	// dump request
	historyData := HistoryData{
		RawRequest:  rawReq.String(),
		RawResponse: rawResp.String(),
	}
	p.addToHistory(historyData)

	return FetchContinueRequest(p.page, e)
}

// syncRequestCookies copies cookies from the shared context jar into the http client jar for the given URL
func syncRequestCookies(sharedJar http.CookieJar, clientJar http.CookieJar, reqURL *url.URL) {
	if sharedJar == nil || clientJar == nil || reqURL == nil {
		return
	}
	if cookies := sharedJar.Cookies(reqURL); len(cookies) > 0 {
		clientJar.SetCookies(reqURL, cookies)
	}
}

// syncResponseCookies copies updated cookies from the http client jar back into the shared context jar for the given URL
func syncResponseCookies(sharedJar http.CookieJar, clientJar http.CookieJar, reqURL *url.URL) {
	if sharedJar == nil || clientJar == nil || reqURL == nil {
		return
	}
	if cookies := clientJar.Cookies(reqURL); len(cookies) > 0 {
		sharedJar.SetCookies(reqURL, cookies)
	}
}
