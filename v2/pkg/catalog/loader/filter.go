package loader

import (
	"errors"
	"strings"
)

// tagFilter is used to filter nuclei tag based execution
type tagFilter struct {
	allowedTags map[string]struct{}
	severities  map[string]struct{}
	authors     map[string]struct{}
	block       map[string]struct{}
	matchAllows map[string]struct{}
}

// ErrExcluded is returned for execluded templates
var ErrExcluded = errors.New("the template was excluded")

// match takes a tag and whether the template was matched from user
// input and returns true or false using a tag filter.
//
// If the tag was specified in deny list, it will not return true
// unless it is explicitly specified by user in includeTags which is the
// matchAllows section.
//
// It returns true if the tag is specified, or false.
func (t *tagFilter) match(tag, author, severity string) (bool, error) {
	_, ok := t.block[tag]
	if ok {
		if _, allowOk := t.matchAllows[tag]; allowOk {
			return true, nil
		}
		return false, ErrExcluded
	}
	matchedAny := false
	if len(t.allowedTags) > 0 {
		_, ok = t.allowedTags[tag]
		if !ok {
			return false, nil
		}
		matchedAny = true
	}
	if len(t.authors) > 0 {
		_, ok = t.authors[author]
		if !ok {
			return false, nil
		}
		matchedAny = true
	}
	if len(t.severities) > 0 {
		_, ok = t.severities[severity]
		if !ok {
			return false, nil
		}
		matchedAny = true
	}
	if len(t.allowedTags) == 0 && len(t.authors) == 0 && len(t.severities) == 0 {
		return true, nil
	}
	return matchedAny, nil
}

// createTagFilter returns a tag filter for nuclei tag based execution
//
// It takes into account Tags, Severities, Authors, IncludeTags, ExcludeTags.
func (config *Config) createTagFilter() *tagFilter {
	filter := &tagFilter{
		allowedTags: make(map[string]struct{}),
		authors:     make(map[string]struct{}),
		severities:  make(map[string]struct{}),
		block:       make(map[string]struct{}),
		matchAllows: make(map[string]struct{}),
	}
	for _, tag := range config.Tags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.allowedTags[val]; !ok {
				filter.allowedTags[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.Severities {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.severities[val]; !ok {
				filter.severities[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.Authors {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.authors[val]; !ok {
				filter.authors[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.ExcludeTags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.block[val]; !ok {
				filter.block[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.IncludeTags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.matchAllows[val]; !ok {
				filter.matchAllows[val] = struct{}{}
			}
			delete(filter.block, val)
		}
	}
	return filter
}

func splitCommaTrim(value string) []string {
	if !strings.Contains(value, ",") {
		return []string{value}
	}
	splitted := strings.Split(value, ",")
	final := make([]string, len(splitted))
	for i, value := range splitted {
		final[i] = strings.TrimSpace(value)
	}
	return final
}
