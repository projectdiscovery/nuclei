package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectPayloads_HTMLTextAllChars(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextHTMLText,
		AvailableChars: CharacterSet{LessThan: true, GreaterThan: true, Slash: true, DoubleQuote: true, SingleQuote: true},
	}
	payloads := SelectPayloads(ref, nil)
	require.NotEmpty(t, payloads)
	require.LessOrEqual(t, len(payloads), 3)
}

func TestSelectPayloads_HTMLTextAngleBracketsFiltered(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextHTMLText,
		AvailableChars: CharacterSet{LessThan: false, GreaterThan: false},
	}
	payloads := SelectPayloads(ref, nil)
	require.Empty(t, payloads, "no payloads should work without < >")
}

func TestSelectPayloads_AttributeDoubleQuoted(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextAttributeDoubleQuoted,
		AvailableChars: CharacterSet{LessThan: true, GreaterThan: true, DoubleQuote: true, Slash: true},
	}
	payloads := SelectPayloads(ref, nil)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_AttributeQuotesFiltered(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextAttributeDoubleQuoted,
		AvailableChars: CharacterSet{LessThan: true, GreaterThan: true, DoubleQuote: false},
	}
	payloads := SelectPayloads(ref, nil)
	require.Empty(t, payloads, "no payloads should work without double quote")
}

func TestSelectPayloads_ScriptString(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextScriptStringSingle,
		AvailableChars: CharacterSet{SingleQuote: true, Slash: true},
	}
	payloads := SelectPayloads(ref, nil)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_URLAttribute(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextURLAttribute,
		AvailableChars: CharacterSet{},
	}
	payloads := SelectPayloads(ref, nil)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_Comment(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextComment,
		AvailableChars: CharacterSet{LessThan: true, GreaterThan: true, Slash: true},
	}
	payloads := SelectPayloads(ref, nil)
	require.NotEmpty(t, payloads)
}

func TestSelectPayloads_MaxAttempts(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextHTMLText,
		AvailableChars: CharacterSet{LessThan: true, GreaterThan: true, Slash: true, DoubleQuote: true, SingleQuote: true, Backtick: true},
	}
	params := map[string]interface{}{"max_verification_attempts": 1}
	payloads := SelectPayloads(ref, params)
	require.Len(t, payloads, 1)
}

func TestSelectPayloads_MaxAttemptsFloat(t *testing.T) {
	ref := ReflectionInfo{
		Context:        ContextHTMLText,
		AvailableChars: CharacterSet{LessThan: true, GreaterThan: true, Slash: true},
	}
	params := map[string]interface{}{"max_verification_attempts": float64(2)}
	payloads := SelectPayloads(ref, params)
	require.LessOrEqual(t, len(payloads), 2)
}

func TestSelectPayloads_UnknownContext(t *testing.T) {
	ref := ReflectionInfo{Context: ContextUnknown}
	payloads := SelectPayloads(ref, nil)
	require.Nil(t, payloads)
}

func TestCanUsePayload_AngleBracketRequired(t *testing.T) {
	require.False(t, canUsePayload("<svg onload=alert(1)>",
		CharacterSet{LessThan: false, GreaterThan: true}, ContextHTMLText))
	require.True(t, canUsePayload("<svg onload=alert(1)>",
		CharacterSet{LessThan: true, GreaterThan: true, Slash: true}, ContextHTMLText))
}

func TestCanUsePayload_BacktickRequired(t *testing.T) {
	require.False(t, canUsePayload("`+alert(1)+`",
		CharacterSet{Backtick: false}, ContextScriptTemplate))
	require.True(t, canUsePayload("`+alert(1)+`",
		CharacterSet{Backtick: true}, ContextScriptTemplate))
}
