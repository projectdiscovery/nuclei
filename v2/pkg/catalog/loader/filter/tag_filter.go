package filter

import (
	"errors"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/internal/severity"
)

// TagFilter is used to filter nuclei templates for tag based execution
type TagFilter struct {
	allowedTags map[string]struct{}
	severities  map[severity.Severity]struct{}
	authors     map[string]struct{}
	block       map[string]struct{}
	matchAllows map[string]struct{}
}

// ErrExcluded is returned for excluded templates
var ErrExcluded = errors.New("the template was excluded")

// Match takes a tag and whether the template was matched from user
// input and returns true or false using a tag filter.
//
// If the tag was specified in deny list, it will not return true
// unless it is explicitly specified by user in includeTags which is the
// matchAllows section.
//
// It returns true if the tag is specified, or false.
func (tagFilter *TagFilter) Match(templateTags, templateAuthors []string, templateSeverity severity.Severity) (bool, error) {
	for _, templateTag := range templateTags {
		_, blocked := tagFilter.block[templateTag]
		_, allowed := tagFilter.matchAllows[templateTag]

		if blocked && !allowed { // the whitelist has precedence over the blacklist
			return false, ErrExcluded
		}
	}

	if !isTagMatch(templateTags, tagFilter) {
		return false, nil
	}

	if !isAuthorMatch(templateAuthors, tagFilter) {
		return false, nil
	}

	if len(tagFilter.severities) > 0 {
		if _, ok := tagFilter.severities[templateSeverity]; !ok {
			return false, nil
		}
	}

	return true, nil
}

func isAuthorMatch(templateAuthors []string, tagFilter *TagFilter) bool {
	if len(tagFilter.authors) == 0 {
		return true
	}

	for _, templateAuthor := range templateAuthors {
		if _, ok := tagFilter.authors[templateAuthor]; ok {
			return true
		}
	}

	return false
}

func isTagMatch(templateTags []string, tagFilter *TagFilter) bool {
	if len(tagFilter.allowedTags) == 0 {
		return true
	}

	for _, templateTag := range templateTags {
		if _, ok := tagFilter.allowedTags[templateTag]; ok {
			return true
		}
	}

	return false
}

// MatchWithWorkflowTags takes an addition list of allowed tags and returns true if the match was successful.
func (tagFilter *TagFilter) MatchWithWorkflowTags(templateTags, templateAuthors []string, templateSeverity severity.Severity, workflowTags []string) (bool, error) {
	workflowAllowedTagMap := make(map[string]struct{})
	for _, workflowTag := range workflowTags {
		if _, ok := workflowAllowedTagMap[workflowTag]; !ok {
			workflowAllowedTagMap[workflowTag] = struct{}{}
		}
	}

	for _, templateTag := range templateTags {
		_, blocked := tagFilter.block[templateTag]
		_, allowed := tagFilter.matchAllows[templateTag]

		if blocked && !allowed { // the whitelist has precedence over the blacklist
			return false, ErrExcluded
		}
	}

	if len(workflowAllowedTagMap) > 0 { // TODO review, does not seem to make sense
		for _, templateTag := range templateTags {
			if _, ok := workflowAllowedTagMap[templateTag]; !ok {
				return false, nil
			}
		}
	}

	if len(tagFilter.authors) > 0 {
		for _, templateAuthor := range templateAuthors {
			if _, ok := tagFilter.authors[templateAuthor]; !ok {
				return false, nil
			}
		}
	}

	if len(tagFilter.severities) > 0 {
		if _, ok := tagFilter.severities[templateSeverity]; !ok {
			return false, nil
		}
	}

	return true, nil
}

type Config struct {
	Tags        []string
	ExcludeTags []string
	Authors     []string
	Severities  severity.Severities
	IncludeTags []string
}

// New returns a tag filter for nuclei tag based execution
//
// It takes into account Tags, Severities, Authors, IncludeTags, ExcludeTags.
func New(config *Config) *TagFilter {
	filter := &TagFilter{
		allowedTags: make(map[string]struct{}),
		authors:     make(map[string]struct{}),
		severities:  make(map[severity.Severity]struct{}),
		block:       make(map[string]struct{}),
		matchAllows: make(map[string]struct{}),
	}
	for _, tag := range config.ExcludeTags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.block[val]; !ok {
				filter.block[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.Severities {
		if _, ok := filter.severities[tag]; !ok {
			filter.severities[tag] = struct{}{}
		}
	}
	for _, tag := range config.Authors {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.authors[val]; !ok {
				filter.authors[val] = struct{}{}
			}
		}
	}
	for _, tag := range config.Tags {
		for _, val := range splitCommaTrim(tag) {
			if _, ok := filter.allowedTags[val]; !ok {
				filter.allowedTags[val] = struct{}{}
			}
			delete(filter.block, val)
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

/*
TODO similar logic is used over and over again. It should be extracted and reused
Changing []string and string data types that hold string slices to StringSlice would be the preferred solution,
which implicitly does the normalization before any other calls starting to use it.
*/
func splitCommaTrim(value string) []string {
	if !strings.Contains(value, ",") {
		return []string{strings.ToLower(value)}
	}
	splitted := strings.Split(value, ",")
	final := make([]string, len(splitted))
	for i, value := range splitted {
		final[i] = strings.ToLower(strings.TrimSpace(value))
	}
	return final
}
