package engine

import (
	"fmt"
	"net/http/httputil"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
)

// routingRuleHandler handles proxy rule for actions related to request/response modification
func (p *Page) routingRuleHandler(ctx *rod.Hijack) {
	// usually browsers don't use chunked transfer encoding, so we set the content-length nevertheless
	ctx.Request.Req().ContentLength = int64(len(ctx.Request.Body()))
	for _, rule := range p.rules {
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

	if p.options.CookieReuse {
		// each http request is performed via the native go http client
		// we first inject the shared cookies
		if cookies := p.input.CookieJar.Cookies(ctx.Request.URL()); len(cookies) > 0 {
			p.instance.browser.httpclient.Jar.SetCookies(ctx.Request.URL(), cookies)
		}
	}

	// perform the request
	_ = ctx.LoadResponse(p.instance.browser.httpclient, true)

	if p.options.CookieReuse {
		// retrieve the updated cookies from the native http client and inject them into the shared cookie jar
		// keeps existing one if not present
		if cookies := p.instance.browser.httpclient.Jar.Cookies(ctx.Request.URL()); len(cookies) > 0 {
			p.input.CookieJar.SetCookies(ctx.Request.URL(), cookies)
		}
	}

	for _, rule := range p.rules {
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
		rawResp.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", respPayloads.ResponseCode, respPayloads.ResponsePhrase))
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

// routingRuleHandlerNative handles native proxy rule
func (p *Page) routingRuleHandlerNative(e *proto.FetchRequestPaused) error {
	// ValidateNFailRequest validates if Local file access is enabled
	// and local network access is enables if not it will fail the request
	// that don't match the rules
	if err := protocolstate.ValidateNFailRequest(p.page, e); err != nil {
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
	rawReq.WriteString(fmt.Sprintf("%s %s %s\n", e.Request.Method, e.Request.URL, "HTTP/1.1"))
	for _, header := range e.Request.Headers {
		rawReq.WriteString(fmt.Sprintf("%s\n", header.String()))
	}
	if e.Request.HasPostData {
		rawReq.WriteString(fmt.Sprintf("\n%s\n", e.Request.PostData))
	}

	// attempts to rebuild the response
	var rawResp strings.Builder
	rawResp.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", statusCode, e.ResponseStatusText))
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
