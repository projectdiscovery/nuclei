package xss

import (
	"strings"

	"golang.org/x/net/html"
)

func DetectReflections(body, marker string) []ReflectionInfo {
	if body == "" || marker == "" || !strings.Contains(body, marker) {
		return nil
	}

	tokenizer := html.NewTokenizer(strings.NewReader(body))
	stack := make([]string, 0, 8)
	reflections := make([]ReflectionInfo, 0, 4)

	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			break
		}

		raw := string(tokenizer.Raw())
		token := tokenizer.Token()

		switch tokenType {
		case html.StartTagToken:
			tagName := strings.ToLower(token.Data)
			reflections = append(reflections, findAttributeReflections(raw, token.Attr, marker, body)...)
			stack = append(stack, tagName)

		case html.SelfClosingTagToken:
			reflections = append(reflections, findAttributeReflections(raw, token.Attr, marker, body)...)

		case html.EndTagToken:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}

		case html.TextToken:
			if !strings.Contains(token.Data, marker) {
				continue
			}
			ctx := classifyTextContext(currentTag(stack), token.Data, marker)
			chars := DetectAvailableChars(token.Data, marker)
			reflections = append(reflections, reflectionForContext(ctx, "", chars))

		case html.CommentToken:
			if strings.Contains(token.Data, marker) {
				chars := DetectAvailableChars(token.Data, marker)
				reflections = append(reflections, reflectionForContext(ContextComment, "", chars))
			}
		}

		if len(reflections) >= maxReflections {
			break
		}
	}
	return reflections
}

func currentTag(stack []string) string {
	if len(stack) == 0 {
		return ""
	}
	return stack[len(stack)-1]
}

func classifyTextContext(tagName, text, marker string) ContextType {
	switch tagName {
	case "script":
		return classifyScriptContext(text, marker)
	case "textarea", "title":
		return ContextRCDATA
	case "style":
		return ContextStyle
	default:
		return ContextHTMLText
	}
}

func classifyScriptContext(scriptText, marker string) ContextType {
	pos := strings.Index(scriptText, marker)
	if pos < 0 {
		return ContextScriptBlock
	}
	var quote rune
	escaped := false
	for _, ch := range scriptText[:pos] {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			quote = ch
		}
	}
	switch quote {
	case '"':
		return ContextScriptStringDouble
	case '\'':
		return ContextScriptStringSingle
	case '`':
		return ContextScriptTemplate
	default:
		return ContextScriptBlock
	}
}

func findAttributeReflections(raw string, attrs []html.Attribute, marker, fullBody string) []ReflectionInfo {
	results := make([]ReflectionInfo, 0, 2)
	for _, attr := range attrs {
		if !strings.Contains(attr.Val, marker) {
			continue
		}
		ctx := classifyAttributeContext(raw, marker)
		if isURLAttribute(attr.Key) && ctx != ContextAttributeUnquoted {
			ctx = ContextURLAttribute
		}
		chars := DetectAvailableChars(attr.Val, marker)
		info := reflectionForContext(ctx, attr.Key, chars)
		results = append(results, info)
	}
	return results
}

func classifyAttributeContext(rawToken, marker string) ContextType {
	markerPos := strings.Index(rawToken, marker)
	if markerPos < 0 {
		return ContextAttributeUnquoted
	}
	eqPos := strings.LastIndex(rawToken[:markerPos], "=")
	if eqPos < 0 {
		return ContextAttributeUnquoted
	}
	i := eqPos + 1
	for i < len(rawToken) && (rawToken[i] == ' ' || rawToken[i] == '\t' || rawToken[i] == '\n' || rawToken[i] == '\r') {
		i++
	}
	if i >= len(rawToken) {
		return ContextAttributeUnquoted
	}
	switch rawToken[i] {
	case '"':
		return ContextAttributeDoubleQuoted
	case '\'':
		return ContextAttributeSingleQuoted
	default:
		return ContextAttributeUnquoted
	}
}

func reflectionForContext(ctx ContextType, attrName string, chars CharacterSet) ReflectionInfo {
	priority := 100
	switch ctx {
	case ContextScriptBlock, ContextScriptStringDouble, ContextScriptStringSingle, ContextScriptTemplate:
		priority = 10
	case ContextURLAttribute:
		priority = 15
	case ContextAttributeUnquoted:
		priority = 20
	case ContextAttributeDoubleQuoted, ContextAttributeSingleQuoted:
		priority = 30
	case ContextHTMLText:
		priority = 40
	case ContextRCDATA:
		priority = 50
	case ContextComment:
		priority = 60
	case ContextStyle:
		priority = 70
	default:
		priority = 80
	}
	return ReflectionInfo{
		Context:        ctx,
		AvailableChars: chars,
		AttributeName:  strings.ToLower(attrName),
		PriorityWeight: priority,
	}
}
