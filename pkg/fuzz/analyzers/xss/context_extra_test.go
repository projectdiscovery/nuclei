package xss

import (
    "testing"
    "strings"
    "golang.org/x/net/html"
)

func TestJavascriptURIContext(t *testing.T) {
    ctx := determineAttributeContext("href", "JaVaScRiPt:alert(1)")
    if ctx != ContextScript {
        t.Errorf("Expected ContextScript for javascript URI, got %v", ctx)
    }
}

func TestSrcdocContext(t *testing.T) {
    ctx := determineAttributeContext("srcdoc", "<div>test</div>")
    if ctx != ContextHTMLText {
        t.Errorf("Expected ContextHTMLText for srcdoc attribute, got %v", ctx)
    }
}

func TestScriptJSONTypeContext(t *testing.T) {
    attrs := []html.Attribute{{Key: "type", Val: "application/json"}}
    ctx := determineScriptContext(attrs)
    if ctx != ContextHTMLText {
        t.Errorf("Expected ContextHTMLText for JSON script type, got %v", ctx)
    }
}

func TestReflectionCaseInsensitive(t *testing.T) {
    a := Analyzer{canary: "TeSt"}
    body := "some text test in body"
    if !a.detectReflection(body) {
        t.Errorf("Expected reflection detected case-insensitively")
    }
}
