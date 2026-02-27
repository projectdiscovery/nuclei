package xss

import (
	"strings"

	gotreesitter "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// classifyCSSContext parses CSS source and determines whether the canary is
// inside a url() function call or a generic CSS value.
func classifyCSSContext(cssSource []byte, canary string) XSSContext {
	lang := grammars.CssLanguage()
	parser := gotreesitter.NewParser(lang)
	tree, err := parser.Parse(cssSource)
	if err != nil {
		return ContextCSSValue
	}
	defer tree.Release()

	bt := gotreesitter.Bind(tree)

	idx := strings.Index(string(cssSource), canary)
	if idx < 0 {
		return ContextCSSValue
	}

	canaryStart := uint32(idx)
	canaryEnd := canaryStart + uint32(len(canary))

	deepest := bt.RootNode().DescendantForByteRange(canaryStart, canaryEnd)
	if deepest == nil {
		return ContextCSSValue
	}

	// Walk up from the deepest node looking for call_expression with "url"
	for node := deepest; node != nil; node = node.Parent() {
		nodeType := bt.NodeType(node)

		if nodeType == "call_expression" {
			funcNode := bt.ChildByField(node, "function")
			if funcNode == nil {
				// Fallback: check first child
				if node.ChildCount() > 0 {
					funcNode = node.Child(0)
				}
			}
			if funcNode != nil {
				funcName := strings.ToLower(bt.NodeText(funcNode))
				if funcName == "url" {
					return ContextCSSURL
				}
			}
		}
	}

	return ContextCSSValue
}
