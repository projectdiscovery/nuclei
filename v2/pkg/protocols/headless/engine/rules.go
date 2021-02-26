package engine

import (
	"fmt"

	"github.com/go-rod/rod"
)

// routingRuleHandler handles proxy rule for actions related to request/response modification
func (p *Page) routingRuleHandler(ctx *rod.Hijack) {
	for _, rule := range p.rules {
		if rule.Part != "request" {
			continue
		}

		if rule.Action == ActionSetMethod {
			ctx.Request.Req().Method = rule.Args["method"]
		} else if rule.Action == ActionAddHeader {
			ctx.Request.Req().Header.Add(rule.Args["key"], rule.Args["value"])
		} else if rule.Action == ActionSetHeader {
			ctx.Request.Req().Header.Set(rule.Args["key"], rule.Args["value"])
		} else if rule.Action == ActionDeleteHeader {
			ctx.Request.Req().Header.Del(rule.Args["key"])
		} else if rule.Action == ActionSetBody {
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
		if rule.Action == ActionAddHeader {
			ctx.Response.Headers().Add(rule.Args["key"], rule.Args["value"])
		} else if rule.Action == ActionSetHeader {
			ctx.Response.Headers().Set(rule.Args["key"], rule.Args["value"])
		} else if rule.Action == ActionDeleteHeader {
			ctx.Response.Headers().Del(rule.Args["key"])
		} else if rule.Action == ActionSetBody {
			body := rule.Args["body"]
			ctx.Response.Headers().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			ctx.Response.SetBody(rule.Args["body"])
		}
	}
}
