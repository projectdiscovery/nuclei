package xss

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var allChars = CharacterSet{
	LessThan: true, GreaterThan: true, DoubleQuote: true,
	SingleQuote: true, Slash: true, Backtick: true,
	Parenthesis: true, Equals: true,
}

func TestSelectPayloads_HTMLTextAllChars(t *testing.T) {
	ref := ReflectionInfo{Context: ContextHTMLText, AvailableChars: allChars}
	got := SelectPayloads(ref, nil)
	require.NotEmpty(t, got)
}

func TestSelectPayloads_HTMLTextAngleBracketsFiltered(t *testing.T) {
	chars := allChars
	chars.LessThan = false
	chars.GreaterThan = false
	ref := ReflectionInfo{Context: ContextHTMLText, AvailableChars: chars}
	got := SelectPayloads(ref, nil)
	require.Empty(t, got, "should filter all HTML text payloads without angle brackets")
}

func TestSelectPayloads_AttributeDoubleQuoted(t *testing.T) {
	ref := ReflectionInfo{Context: ContextAttributeDoubleQuoted, AvailableChars: allChars}
	got := SelectPayloads(ref, nil)
	require.NotEmpty(t, got)
}

func TestSelectPayloads_AttributeQuotesFiltered(t *testing.T) {
	chars := allChars
	chars.DoubleQuote = false
	ref := ReflectionInfo{Context: ContextAttributeDoubleQuoted, AvailableChars: chars}
	got := SelectPayloads(ref, nil)
	require.Empty(t, got, "should filter all attr payloads without double quotes")
}

func TestSelectPayloads_ScriptString(t *testing.T) {
	ref := ReflectionInfo{Context: ContextScriptStringDouble, AvailableChars: allChars}
	got := SelectPayloads(ref, nil)
	require.NotEmpty(t, got)
}

func TestSelectPayloads_URLAttribute(t *testing.T) {
	ref := ReflectionInfo{Context: ContextURLAttribute, AvailableChars: allChars}
	got := SelectPayloads(ref, nil)
	require.NotEmpty(t, got)
}

func TestSelectPayloads_Comment(t *testing.T) {
	ref := ReflectionInfo{Context: ContextComment, AvailableChars: allChars}
	got := SelectPayloads(ref, nil)
	require.NotEmpty(t, got)
}

func TestSelectPayloads_EventHandler(t *testing.T) {
	ref := ReflectionInfo{Context: ContextEventHandler, AvailableChars: allChars}
	got := SelectPayloads(ref, nil)
	require.NotEmpty(t, got)
	// Event handler payloads should include alert(1)
	found := false
	for _, p := range got {
		if p == "alert(1)" {
			found = true
		}
	}
	require.True(t, found)
}

func TestSelectPayloads_EventHandlerNoParens(t *testing.T) {
	chars := allChars
	chars.Parenthesis = false
	ref := ReflectionInfo{Context: ContextEventHandler, AvailableChars: chars}
	got := SelectPayloads(ref, nil)
	// alert`1` doesn't use parentheses, should survive
	for _, p := range got {
		require.NotContains(t, p, "(")
	}
}

func TestSelectPayloads_MaxAttempts(t *testing.T) {
	ref := ReflectionInfo{Context: ContextHTMLText, AvailableChars: allChars}
	params := map[string]interface{}{"max_verification_attempts": 1}
	got := SelectPayloads(ref, params)
	require.Len(t, got, 1)
}

func TestSelectPayloads_MaxAttemptsFloat(t *testing.T) {
	ref := ReflectionInfo{Context: ContextHTMLText, AvailableChars: allChars}
	params := map[string]interface{}{"max_verification_attempts": float64(2)}
	got := SelectPayloads(ref, params)
	require.LessOrEqual(t, len(got), 2)
}

func TestSelectPayloads_UnknownContext(t *testing.T) {
	ref := ReflectionInfo{Context: ContextUnknown, AvailableChars: allChars}
	got := SelectPayloads(ref, nil)
	require.Nil(t, got)
}

func TestCanUsePayload_AngleBracketRequired(t *testing.T) {
	payload := "<img src=x onerror=alert(1)>"
	require.True(t, canUsePayload(payload, allChars, ContextHTMLText))
	noAngles := allChars
	noAngles.LessThan = false
	require.False(t, canUsePayload(payload, noAngles, ContextHTMLText))
}

func TestCanUsePayload_BacktickRequired(t *testing.T) {
	payload := "`+alert(1)+`"
	require.True(t, canUsePayload(payload, allChars, ContextScriptTemplate))
	noBacktick := allChars
	noBacktick.Backtick = false
	require.False(t, canUsePayload(payload, noBacktick, ContextScriptTemplate))
}

func TestCanUsePayload_ParenthesisRequired(t *testing.T) {
	payload := "alert(1)"
	require.True(t, canUsePayload(payload, allChars, ContextEventHandler))
	noParens := allChars
	noParens.Parenthesis = false
	require.False(t, canUsePayload(payload, noParens, ContextEventHandler))
}
