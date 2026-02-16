package xsscontext

import "testing"

func TestDetectContext_HTML(t *testing.T) {
	m := "XSSCTX1234"
	body := "<div>" + m + "</div>"
	if got := detectContext(body, m); got != ContextHTML {
		t.Fatalf("expected %s got %s", ContextHTML, got)
	}
}

func TestDetectContext_Attribute(t *testing.T) {
	m := "XSSCTX1234"
	body := `<input value="` + m + `">`
	if got := detectContext(body, m); got != ContextAttribute {
		t.Fatalf("expected %s got %s", ContextAttribute, got)
	}
}

func TestDetectContext_JS(t *testing.T) {
	m := "XSSCTX1234"
	body := `<script>var a="` + m + `"</script>`
	if got := detectContext(body, m); got != ContextJS {
		t.Fatalf("expected %s got %s", ContextJS, got)
	}
}

func TestDetectContext_URL(t *testing.T) {
	m := "XSSCTX1234"
	body := `<a href="` + m + `">link</a>`
	if got := detectContext(body, m); got != ContextURL {
		t.Fatalf("expected %s got %s", ContextURL, got)
	}
}

