package waf

import "unicode/utf8"

type literalMatcherNode struct {
	next    [256]int32
	failure int32
	outputs []string
}

// literalMatcher finds every configured byte string in one pass over the
// response. WAF responses can be several megabytes, so scanning once is much
// cheaper than searching the response once for every WAF signature.
type literalMatcher struct {
	nodes []literalMatcherNode
}

func newLiteralMatcher(patterns []string) *literalMatcher {
	if len(patterns) == 0 {
		return nil
	}

	matcher := &literalMatcher{nodes: []literalMatcherNode{newLiteralMatcherNode()}}
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}

		state := int32(0)
		for index := 0; index < len(pattern); index++ {
			value := pattern[index]
			next := matcher.nodes[state].next[value]
			if next == -1 {
				next = int32(len(matcher.nodes))
				matcher.nodes = append(matcher.nodes, newLiteralMatcherNode())
				matcher.nodes[state].next[value] = next
			}
			state = next
		}
		matcher.nodes[state].outputs = append(matcher.nodes[state].outputs, pattern)
	}

	queue := make([]int32, 0, len(matcher.nodes))
	for value := 0; value < 256; value++ {
		child := matcher.nodes[0].next[byte(value)]
		if child == -1 {
			matcher.nodes[0].next[byte(value)] = 0
			continue
		}
		matcher.nodes[child].failure = 0
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for value := 0; value < 256; value++ {
			child := matcher.nodes[state].next[byte(value)]
			if child == -1 {
				matcher.nodes[state].next[byte(value)] = matcher.nodes[matcher.nodes[state].failure].next[byte(value)]
				continue
			}
			failure := matcher.nodes[matcher.nodes[state].failure].next[byte(value)]
			matcher.nodes[child].failure = failure
			matcher.nodes[child].outputs = append(matcher.nodes[child].outputs, matcher.nodes[failure].outputs...)
			queue = append(queue, child)
		}
	}
	return matcher
}

func newLiteralMatcherNode() literalMatcherNode {
	node := literalMatcherNode{}
	for index := range node.next {
		node.next[index] = -1
	}
	return node
}

func (m *literalMatcher) find(content string) map[string]struct{} {
	found := make(map[string]struct{})
	if m == nil || len(m.nodes) == 0 {
		return found
	}

	state := int32(0)
	for index := 0; index < len(content); index++ {
		state = m.nodes[state].next[content[index]]
		for _, pattern := range m.nodes[state].outputs {
			found[pattern] = struct{}{}
		}
	}
	return found
}

// findExactAndASCIIFolded advances the case-sensitive and ASCII-folded
// matchers together, avoiding a second copy and traversal of large responses.
func findExactAndASCIIFolded(content string, exactMatcher, foldedMatcher *literalMatcher) (map[string]struct{}, map[string]struct{}) {
	exactFound := make(map[string]struct{})
	foldedFound := make(map[string]struct{})
	var exactState, foldedState int32
	for index := 0; index < len(content); index++ {
		value := content[index]
		if exactMatcher != nil {
			exactState = exactMatcher.nodes[exactState].next[value]
			for _, pattern := range exactMatcher.nodes[exactState].outputs {
				exactFound[pattern] = struct{}{}
			}
		}
		if foldedMatcher != nil {
			if value >= 'a' && value <= 'z' {
				value -= 'a' - 'A'
			}
			foldedState = foldedMatcher.nodes[foldedState].next[value]
			for _, pattern := range foldedMatcher.nodes[foldedState].outputs {
				foldedFound[pattern] = struct{}{}
			}
		}
	}
	return exactFound, foldedFound
}

func mergeLiteralMatches(destination, source map[string]struct{}) {
	for pattern := range source {
		destination[pattern] = struct{}{}
	}
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
