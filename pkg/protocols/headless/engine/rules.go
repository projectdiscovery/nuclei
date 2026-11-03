package engine

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// routingRuleHandler handles proxy rule for actions related to request/response modification
func (p *Page) routingRuleHandler(httpClient *http.Client) func(ctx *rod.Hijack) {
	return func(ctx *rod.Hijack) {
		req := ctx.Request.Req()
		// go-rod discards url.Parse errors, so a URL that Chrome accepts but
		// net/url rejects, such as "/100%.png", arrives as nil. Fail the request:
		// the Go client cannot send it, and continuing it in the browser would
		// drop the modification rules and, with -cdp-endpoint (no headless
		// proxy), the network policy's dial-time address checks.
		if req.URL == nil {
			gologger.Verbose().Msgf("headless: failed %s request with a URL that net/url cannot parse", req.Method)
			ctx.Response.Fail(proto.NetworkErrorReasonFailed)

			return
		}

		// usually browsers don't use chunked transfer encoding, so we set the content-length nevertheless
		req.ContentLength = int64(len(ctx.Request.Body()))
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
					req.Method = rule.Args["method"]
				})
			case ActionAddHeader:
				req.Header.Add(rule.Args["key"], rule.Args["value"])
			case ActionSetHeader:
				req.Header.Set(rule.Args["key"], rule.Args["value"])
			case ActionDeleteHeader:
				req.Header.Del(rule.Args["key"])
			case ActionSetBody:
				body := rule.Args["body"]
				req.ContentLength = int64(len(body))
				ctx.Request.SetBody(body)
			}
		}

		// each http request is performed via the native go http client
		// we first inject the shared cookies
		if !p.options.DisableCookie {
			if cookies := p.ctx.CookieJar.Cookies(req.URL); len(cookies) > 0 {
				httpClient.Jar.SetCookies(req.URL, cookies)
			}
		}

		// perform the request
		if err := ctx.LoadResponse(httpClient, true); err != nil {
			gologger.Verbose().Msgf("headless: failed to load response for %s: %s", req.URL, err)
		}

		if !p.options.DisableCookie {
			// retrieve the updated cookies from the native http client and inject them into the shared cookie jar
			// keeps existing one if not present
			if cookies := httpClient.Jar.Cookies(req.URL); len(cookies) > 0 {
				p.ctx.CookieJar.SetCookies(req.URL, cookies)
			}
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
