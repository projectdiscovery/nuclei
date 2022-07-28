package filter

import (
	"strings"
)

// TagOperation is a struct that holds the tags to be matched and the result of the match based on && operator
type TagOperation struct {
	matched     bool
	normalTags  []string
	logicalTags []string
}

// hasAND checks if the tag has the AND operator
func (tagOperation *TagOperation) hasAND(value string) bool {
	return strings.Contains(value, "&&")
}

// Parse the tags into normal and logical tags
func (tagOperation *TagOperation) Parse(tags interface{}) {
	switch tags := tags.(type) {
	case string:
		tagOperation.normalTags = append(tagOperation.normalTags, tags)
	case map[string]struct{}:
		for tag := range tags {
			if tagOperation.hasAND(tag) {
				tagOperation.logicalTags = append(tagOperation.logicalTags, tag)
			} else {
				tagOperation.Parse(tag)
			}
		}
	}
}

// Match the tags against the normal and logical tags
func (tagOperation *TagOperation) Match(tag []string) bool {
	// check if tags are empty
	if len(tagOperation.logicalTags) == 0 && len(tagOperation.normalTags) == 0 {
		return true
	}
	for _, l := range tagOperation.logicalTags {
		AND := strings.Split(l, "&&")
		matchCount := 0
		for _, t := range tag {
			for _, a := range AND {
				if t == strings.TrimSpace(a) {
					matchCount++
				}
			}
		}
		if matchCount >= len(AND) {
			tagOperation.matched = true
		}
	}
	for _, t := range tagOperation.normalTags {
		for _, tag := range tag {
			if t == tag {
				tagOperation.matched = true
			}
		}
	}
	return tagOperation.matched
}
