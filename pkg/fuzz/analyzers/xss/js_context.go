package xss

import (
	"strings"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

const maxScriptSourceBytes = 100 * 1024
const maxParseNestingDepth = 500

// classifyJSContext parses JavaScript source and determines the sub-context
// of a canary reflection.
func classifyJSContext(jsSource []byte, canary string) XSSContext {
	if len(jsSource) > maxScriptSourceBytes {
		return ContextScriptExpression
	}
	if exceedsNestingDepth(jsSource, maxParseNestingDepth) {
		return ContextScriptExpression
	}

	lang := grammars.JavascriptLanguage()
	parser := gotreesitter.NewParser(lang)
	var (
		tree *gotreesitter.Tree
		err  error
	)
	func() {
		defer func() {
			if recover() != nil {
				tree = nil
			}
		}()
		tree, err = parser.Parse(jsSource)
	}()
	if err != nil {
		return ContextScriptExpression
	}
	if tree == nil {
		return ContextScriptExpression
	}
	defer tree.Release()

	bt := gotreesitter.Bind(tree)

	// Find the byte offset of the canary in the JS source
	idx := strings.Index(string(jsSource), canary)
	if idx < 0 {
		return ContextScriptExpression
	}

	canaryStart := uint32(idx)
	canaryEnd := canaryStart + uint32(len(canary))

	// Find the deepest node containing the canary
	deepest := bt.RootNode().DescendantForByteRange(canaryStart, canaryEnd)
	if deepest == nil {
		return ContextScriptExpression
	}

	// Walk up from the deepest node to classify context
	for node := deepest; node != nil; node = node.Parent() {
		nodeType := bt.NodeType(node)

		switch nodeType {
		case "string":
			// Determine single vs double quoted
			text := bt.NodeText(node)
			if len(text) > 0 {
				switch text[0] {
				case '"':
					return ContextScriptStringDouble
				case '\'':
					return ContextScriptStringSingle
				}
			}
			return ContextScriptStringDouble

		case "template_string":
			return ContextScriptTemplateLiteral

		case "comment":
			text := bt.NodeText(node)
			if strings.HasPrefix(text, "/*") {
				return ContextScriptBlockComment
			}
			return ContextScriptComment

		case "program":
			// Reached the root without matching anything specific
			return ContextScriptExpression
		}
	}

	return ContextScriptExpression
}

// exceedsNestingDepth returns true when bracket nesting exceeds maxDepth.
// This is a lightweight pre-parse guard against extremely deep parser inputs.
func exceedsNestingDepth(source []byte, maxDepth int) bool {
	depth := 0
	for _, ch := range source {
		switch ch {
		case '{', '[', '(':
			depth++
			if depth > maxDepth {
				return true
			}
		case '}', ']', ')':
			if depth > 0 {
				depth--
			}
		}
	}
	return false
}
