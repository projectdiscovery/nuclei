package xsscontext

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"golang.org/x/net/html"
)

// xssContextAnalyzer analyzes HTML response to detect XSS context
type xssContextAnalyzer struct{}

// Name returns analyzer name
func (a *xssContextAnalyzer) Name() string {
	return "xss-context"
}

// ApplyInitialTransformation applies transformations before analysis
func (a *xssContextAnalyzer) ApplyInitialTransformation(data string, _ map[string]interface{}) string {
	return analyzers.ApplyPayloadTransformations(data)
}

// Analyze determines if payload is reflected in dangerous HTML context
func (a *xssContextAnalyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	resp := options.FuzzGenerated.Response
	if resp == nil || resp.Body == nil {
		return false, "no response body", nil
	}

	body := string(resp.Body)
	payload := options.FuzzGenerated.Value

	// Check if our payload is reflected
	if payload == "" || !strings.Contains(body, payload) {
		return false, "payload not reflected", nil
	}

	// Detect context using DOM parsing
	reflectionCtx := detectContext(body, payload)

	switch reflectionCtx {
	case "script":
		return true, "reflected in script context - high risk", nil
	case "attribute":
		return true, "reflected in HTML attribute - high risk", nil
	case "event":
		return true, "reflected in event handler - critical", nil
	case "url":
		return true, "reflected in URL context - high risk", nil
	case "comment":
		return true, "reflected in HTML comment", nil
	default:
		return true, "reflected in body", nil
	}
}

func detectContext(body, payload string) string {
	// Parse HTML using golang.org/x/net/html
	 tokenizer := html.NewTokenizer(strings.NewReader(body))
	 
	 var currentAttr string
	 for {
		 tt := tokenizer.Next()
		 switch tt {
		 case html.StartTagToken:
			 tagName, _ := tokenizer.TagName()
			 // Check for event handlers before processing attributes
			 for _, attr := range tokenizer.Attr() {
				 if isEventHandler(attr.Key) {
					 return "event"
				 }
				 if attr.Key == "href" {
					 currentAttr = "href"
				 }
			 }
			 // Check if payload is in script tag
			 if strings.ToLower(string(tagName)) == "script" {
				 return "script"
			 }
			 
		 case html.TextToken:
			 text := tokenizer.Text()
			 if strings.Contains(text, payload) {
				 if currentAttr == "href" {
					 return "url"
				 }
				 return "attribute"
			 }
			 
		 case html.CommentToken:
			 comment := tokenizer.Text()
			 if strings.Contains(comment, payload) {
				 return "comment"
			 }
			 
		 case html.EndTagToken:
			 currentAttr = ""
			 
		 case html.ErrorToken:
			 return "body"
		 }
	 }
}

func isEventHandler(attrName string) bool {
	handlers := map[string]bool{
		"onerror":  true,
		"onload":   true,
		"onclick":  true,
		"onmouseover": true,
		"onfocus":   true,
		"onblur":    true,
		"oninput":   true,
		"onchange":   true,
		"onsubmit":  true,
	}
	return handlers[strings.ToLower(attrName)]
}

func init() {
	analyzers.RegisterAnalyzer("xss-context", &xssContextAnalyzer{})
}
