package engine

import (
	"fmt"

	"github.com/go-rod/rod"
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
			ctx.Request.Req().Method = rule.Args["method"]
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
	_ = ctx.LoadResponse(p.instance.browser.httpclient, true)

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
}
