package xss

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// AnalysisResult represents the result of XSS context analysis
type AnalysisResult struct {
	// Context is the type of XSS context detected
	Context ContextType
	// ReflectedCanary is the portion of the canary that was reflected
	ReflectedCanary string
	// TagName is the HTML tag name containing the reflection (if applicable)
	TagName string
	// AttributeName is the attribute name containing the reflection (if applicable)
	AttributeName string
	// AttributeValue is the value of the attribute containing the reflection
	AttributeValue string
}

// AnalyzeContext analyzes the response body to determine the XSS context
// of the reflected canary using the HTML tokenizer
func AnalyzeContext(body, canary string) *AnalysisResult {
	// Case-insensitive search for the canary
	lowerBody := strings.ToLower(body)
	lowerCanary := strings.ToLower(canary)
	canaryIndex := strings.Index(lowerBody, lowerCanary)
	if canaryIndex == -1 {
		return &AnalysisResult{Context: ContextNone}
	}

	// Extract the actual reflected canary (preserving original case from body)
	reflectedCanary := body[canaryIndex : canaryIndex+len(canary)]

	// Use the HTML tokenizer to determine context
	tokenizer := html.NewTokenizer(strings.NewReader(body))

	// Track state for script blocks
	inScriptBlock := false
	inJSONScriptBlock := false
	currentScriptTag := ""

	for {
		tt := tokenizer.Next()
		if tt == html.ErrorToken {
			if err := tokenizer.Err(); err == io.EOF {
				break
			}
			continue
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tagName, hasAttr := tokenizer.TagName()
			tagNameStr := string(tagName)

			// Check if reflection is inside the tag name itself
			tokenStart := tokenizer.Token().Data
			if tokenStart != "" {
				tokenPos := strings.Index(strings.ToLower(tokenStart), lowerCanary)
				if tokenPos != -1 {
					return &AnalysisResult{
						Context:         ContextHTMLText,
						ReflectedCanary: reflectedCanary,
						TagName:         tagNameStr,
					}
				}
			}

			if hasAttr {
				var attrName, attrValue string
				for {
					attrNameB, attrValueB, more := tokenizer.TagAttr()
					attrName = string(attrNameB)
					attrValue = string(attrValueB)

					// Check if the canary is in this attribute value
					if strings.Contains(strings.ToLower(attrValue), lowerCanary) {
						// Check for javascript: URI - the attribute value starts with javascript:
						if strings.HasPrefix(strings.ToLower(strings.TrimSpace(attrValue)), "javascript:") {
							return &AnalysisResult{
								Context:         ContextScriptURI,
								ReflectedCanary: reflectedCanary,
								TagName:         tagNameStr,
								AttributeName:   attrName,
								AttributeValue:  attrValue,
							}
						}

						// Check for srcdoc attribute - treat as HTML injection context
						if strings.EqualFold(attrName, "srcdoc") {
							return &AnalysisResult{
								Context:         ContextHTMLText,
								ReflectedCanary: reflectedCanary,
								TagName:         tagNameStr,
								AttributeName:   attrName,
								AttributeValue:  attrValue,
							}
						}

						// Check if the attribute value is quoted
						token := tokenizer.Token()
						if token.Type == html.StartTagToken {
							// Determine if the attribute is quoted
							// by checking the raw tag representation
							raw := string(tokenizer.Raw())
							attrInRaw := strings.Index(raw, attrName+"=")
							if attrInRaw != -1 {
								afterEquals := raw[attrInRaw+len(attrName)+1:]
								if strings.HasPrefix(afterEquals, "\"") || strings.HasPrefix(afterEquals, "'") {
									return &AnalysisResult{
										Context:         ContextAttribute,
										ReflectedCanary: reflectedCanary,
										TagName:         tagNameStr,
										AttributeName:   attrName,
										AttributeValue:  attrValue,
									}
								}
								return &AnalysisResult{
									Context:         ContextAttributeUnquoted,
									ReflectedCanary: reflectedCanary,
									TagName:         tagNameStr,
									AttributeName:   attrName,
									AttributeValue:  attrValue,
								}
							}
						}
						return &AnalysisResult{
							Context:         ContextAttribute,
							ReflectedCanary: reflectedCanary,
							TagName:         tagNameStr,
							AttributeName:   attrName,
							AttributeValue:  attrValue,
						}
					}

					if !more {
						break
					}
				}
			}

			// Track script block entry
			if strings.EqualFold(tagNameStr, "script") {
				inScriptBlock = true
				// Check if it's a JSON script block (non-executable)
				currentScriptTag = ""
				if hasAttr {
					for {
						name, value, more := tokenizer.TagAttr()
						if strings.EqualFold(string(name), "type") {
							currentScriptTag = strings.ToLower(strings.TrimSpace(string(value)))
						}
						if !more {
							break
						}
					}
				}
				if isJSONScriptType(currentScriptTag) {
					inJSONScriptBlock = true
				}
			}

		case html.TextToken:
			text := string(tokenizer.Text())
			if strings.Contains(strings.ToLower(text), lowerCanary) {
				if inJSONScriptBlock {
					return &AnalysisResult{
						Context:         ContextJSONScript,
						ReflectedCanary: reflectedCanary,
						TagName:         "script",
					}
				}
				if inScriptBlock {
					// Determine if it's inside a string context
					if isInsideJSString(text, canary) {
						return &AnalysisResult{
							Context:         ContextScriptString,
							ReflectedCanary: reflectedCanary,
							TagName:         "script",
						}
					}
					return &AnalysisResult{
						Context:         ContextScript,
						ReflectedCanary: reflectedCanary,
						TagName:         "script",
					}
				}
				return &AnalysisResult{
					Context:         ContextHTMLText,
					ReflectedCanary: reflectedCanary,
				}
			}

		case html.EndTagToken:
			tagName, _ := tokenizer.TagName()
			if strings.EqualFold(string(tagName), "script") {
				inScriptBlock = false
				inJSONScriptBlock = false
				currentScriptTag = ""
			}

		case html.CommentToken:
			comment := string(tokenizer.Text())
			if strings.Contains(strings.ToLower(comment), lowerCanary) {
				return &AnalysisResult{
					Context:         ContextHTMLComment,
					ReflectedCanary: reflectedCanary,
				}
			}
		}
	}

	// Fallback: canary found in body but no specific context detected
	return &AnalysisResult{
		Context:         ContextHTMLText,
		ReflectedCanary: reflectedCanary,
	}
}

// isJSONScriptType returns true if the script type indicates non-executable JSON content
func isJSONScriptType(scriptType string) bool {
	switch scriptType {
	case "application/json", "application/ld+json", "application/json+ld",
		"text/json", "importmap":
		return true
	}
	return strings.HasPrefix(scriptType, "application/") &&
		strings.HasSuffix(scriptType, "+json")
}

// isInsideJSString determines if the canary position is inside a JavaScript string literal
func isInsideJSString(text, canary string) bool {
	idx := strings.Index(strings.ToLower(text), strings.ToLower(canary))
	if idx < 0 {
		return false
	}

	// Look backwards from canary position for string delimiters
	before := text[:idx]
	singleCount := strings.Count(before, "'")
	doubleCount := strings.Count(before, "\"")
	backtickCount := strings.Count(before, "`")

	// If any quote type appears an odd number of times before the canary,
	// we're likely inside a string
	if singleCount%2 != 0 || doubleCount%2 != 0 || backtickCount%2 != 0 {
		return true
	}
	return false
}
