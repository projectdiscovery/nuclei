package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectPayloads_HTMLText_AllCharsAvailable(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		SingleQuote:   true,
		DoubleQuote:   true,
		ForwardSlash:  true,
		Backtick:      true,
		Parentheses:   true,
		Equals:        true,
	}
	payloads := SelectPayloads(ContextHTMLText, chars)
	require.NotEmpty(t, payloads)
	// All HTML text payloads require angle brackets and parentheses
	for _, p := range payloads {
		require.Contains(t, p, "<", "payload %q should contain <", p)
	}
}

func TestSelectPayloads_HTMLText_NoBrackets(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: false,
		SingleQuote:   true,
		DoubleQuote:   true,
		ForwardSlash:  true,
		Parentheses:   true,
		Equals:        true,
	}
	payloads := SelectPayloads(ContextHTMLText, chars)
	// Without angle brackets, HTML text payloads should be filtered out
	require.Empty(t, payloads)
}

func TestSelectPayloads_Attribute_AllChars(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		SingleQuote:   true,
		DoubleQuote:   true,
		ForwardSlash:  true,
		Parentheses:   true,
		Equals:        true,
	}
	payloads := SelectPayloads(ContextAttribute, chars)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_Attribute_NoDoubleQuote(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		SingleQuote:   true,
		DoubleQuote:   false,
		ForwardSlash:  true,
		Parentheses:   true,
		Equals:        true,
	}
	payloads := SelectPayloads(ContextAttribute, chars)
	// Should still have some payloads (single-quote variants)
	require.NotEmpty(t, payloads)
	// None should contain a double quote
	for _, p := range payloads {
		require.NotContains(t, p, `"`, "payload should not need double quote: %s", p)
	}
}

func TestSelectPayloads_Script(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		ForwardSlash:  true,
		Parentheses:   true,
	}
	payloads := SelectPayloads(ContextScript, chars)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_ScriptString(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		SingleQuote:   true,
		DoubleQuote:   true,
		ForwardSlash:  true,
		Parentheses:   true,
		Backtick:      true,
	}
	payloads := SelectPayloads(ContextScriptString, chars)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_Comment(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		ForwardSlash:  true,
		Parentheses:   true,
		Equals:        true,
	}
	payloads := SelectPayloads(ContextHTMLComment, chars)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_Style(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		ForwardSlash:  true,
		Parentheses:   true,
		Equals:        true,
	}
	payloads := SelectPayloads(ContextStyle, chars)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_UnknownContext(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		SingleQuote:   true,
		DoubleQuote:   true,
	}
	payloads := SelectPayloads(ContextNone, chars)
	require.Nil(t, payloads)
}

func TestPayloadRequirements(t *testing.T) {
	reqs := payloadRequirements(`"><script>alert(1)</script>`)
	require.True(t, reqs.AngleBrackets)
	require.True(t, reqs.DoubleQuote)
	require.True(t, reqs.ForwardSlash)
	require.True(t, reqs.Parentheses)
	require.False(t, reqs.SingleQuote)
	require.False(t, reqs.Backtick)
}

func TestCanUsePayload_AllAvailable(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		SingleQuote:   true,
		DoubleQuote:   true,
		ForwardSlash:  true,
		Parentheses:   true,
		Backtick:      true,
		Equals:        true,
	}
	require.True(t, canUsePayload(`<script>alert(1)</script>`, chars))
}

func TestCanUsePayload_MissingBrackets(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: false,
		Parentheses:   true,
		ForwardSlash:  true,
	}
	require.False(t, canUsePayload(`<script>alert(1)</script>`, chars))
}

func TestCanUsePayload_MissingParens(t *testing.T) {
	chars := CharacterSet{
		AngleBrackets: true,
		Parentheses:   false,
		ForwardSlash:  true,
	}
	require.False(t, canUsePayload(`<script>alert(1)</script>`, chars))
}
