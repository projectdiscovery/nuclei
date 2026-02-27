package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyzerName(t *testing.T) {
	a := &Analyzer{}
	require.Equal(t, "xss_context", a.Name())
}

func TestApplyInitialTransformation_CanaryReplacement(t *testing.T) {
	a := &Analyzer{}
	params := make(map[string]interface{})
	result := a.ApplyInitialTransformation("test=[XSS_CANARY]&foo=bar", params)

	// The canary placeholder should be replaced with the generated value.
	require.NotContains(t, result, "[XSS_CANARY]")
	// The canary should be stored in params.
	canary, ok := params["xss_canary"]
	require.True(t, ok, "xss_canary should be set in params")
	require.NotEmpty(t, canary)
	require.Contains(t, result, canary.(string))
}

func TestApplyInitialTransformation_CustomCanary(t *testing.T) {
	a := &Analyzer{}
	params := map[string]interface{}{
		"canary": "my_custom_canary<>\"'",
	}
	result := a.ApplyInitialTransformation("q=[XSS_CANARY]", params)
	require.Contains(t, result, "my_custom_canary<>\"'")
	require.Equal(t, "my_custom_canary<>\"'", params["xss_canary"])
}

func TestApplyInitialTransformation_NoPlaceholder(t *testing.T) {
	a := &Analyzer{}
	params := make(map[string]interface{})
	result := a.ApplyInitialTransformation("test=[RANDSTR]&id=[RANDNUM]", params)

	// RANDSTR and RANDNUM should be replaced, but no canary.
	require.NotContains(t, result, "[RANDSTR]")
	require.NotContains(t, result, "[RANDNUM]")
	_, ok := params["xss_canary"]
	require.False(t, ok, "xss_canary should not be set without placeholder")
}

func TestApplyInitialTransformation_NilParams(t *testing.T) {
	a := &Analyzer{}
	// Should not panic with nil params.
	result := a.ApplyInitialTransformation("test=[XSS_CANARY]", nil)
	require.NotContains(t, result, "[XSS_CANARY]")
}

func TestVerifyReplayBody_HTMLText(t *testing.T) {
	body := `<html><body><script>alert(1)</script></body></html>`
	require.True(t, verifyReplayBody(body, "<script>alert(1)</script>", ContextHTMLText))
}

func TestVerifyReplayBody_HTMLText_Encoded(t *testing.T) {
	// If the server entity-encodes the payload, it should NOT verify.
	body := `<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>`
	require.False(t, verifyReplayBody(body, "<script>alert(1)</script>", ContextHTMLText))
}

func TestVerifyReplayBody_Attribute(t *testing.T) {
	body := `<html><body><input value="" onfocus=alert(1) autofocus=""></body></html>`
	payload := `" onfocus=alert(1) autofocus="`
	require.True(t, verifyReplayBody(body, payload, ContextAttribute))
}

func TestVerifyReplayBody_Script(t *testing.T) {
	body := `<html><script>;alert(1)//</script></html>`
	require.True(t, verifyReplayBody(body, ";alert(1)//", ContextScript))
}

func TestVerifyReplayBody_Comment(t *testing.T) {
	body := `<html><!--user: --><script>alert(1)</script>--><body></body></html>`
	payload := "--><script>alert(1)</script>"
	require.True(t, verifyReplayBody(body, payload, ContextHTMLComment))
}

func TestVerifyReplayBody_Style(t *testing.T) {
	body := `<html><style></style><script>alert(1)</script></style><body></body></html>`
	payload := "</style><script>alert(1)</script>"
	require.True(t, verifyReplayBody(body, payload, ContextStyle))
}

func TestVerifyReplayBody_PayloadNotPresent(t *testing.T) {
	body := `<html><body>safe content</body></html>`
	require.False(t, verifyReplayBody(body, "<script>alert(1)</script>", ContextHTMLText))
}

func TestRandAlphaNum(t *testing.T) {
	s := randAlphaNum(8)
	require.Len(t, s, 8)
	for _, c := range s {
		require.True(t, (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'),
			"character %c should be alphanumeric lowercase", c)
	}
}
