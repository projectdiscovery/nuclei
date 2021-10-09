package filter

import (
	"errors"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
)

// TagFilter is used to filter nuclei templates for tag based execution
type TagFilter struct {
	allowedTags       map[string]struct{}
	severities        map[severity.Severity]struct{}
	excludeSeverities map[severity.Severity]struct{}
	authors           map[string]struct{}
	block             map[string]struct{}
	matchAllows       map[string]struct{}
}

// ErrExcluded is returned for excluded templates
var ErrExcluded = errors.New("the template was excluded")

// Match filters templates based on user provided tags, authors, extraTags and severity.
// If the template contains tags specified in the deny-list, it will not be matched
// unless it is explicitly specified by user using the includeTags (matchAllows field).
// Matching rule: (tag1 OR tag2...) AND (author1 OR author2...) AND (severity1 OR severity2...) AND (extraTags1 OR extraTags2...)
// Returns true if the template matches the filter criteria, false otherwise.
func (tagFilter *TagFilter) Match(templateTags, templateAuthors []string, templateSeverity severity.Severity, extraTags []string) (bool, error) {
	for _, templateTag := range templateTags {
		_, blocked := tagFilter.block[templateTag]
		_, allowed := tagFilter.matchAllows[templateTag]

		if blocked && !allowed { // the whitelist has precedence over the blacklist
			return false, ErrExcluded
		}
	}

	if !isExtraTagMatch(extraTags, templateTags) {
		return false, nil
	}

	if !isTagMatch(tagFilter, templateTags) {
		return false, nil
	}

	if !isAuthorMatch(tagFilter, templateAuthors) {
		return false, nil
	}

	if !isSeverityMatch(tagFilter, templateSeverity) {
		return false, nil
	}

	return true, nil
}

func isSeverityMatch(tagFilter *TagFilter, templateSeverity severity.Severity) bool {
	if (len(tagFilter.excludeSeverities) == 0 && len(tagFilter.severities) == 0) || templateSeverity == severity.Undefined {
		return true
	}

	included := true
	if len(tagFilter.severities) > 0 {
		_, included = tagFilter.severities[templateSeverity]
	}

	excluded := false
	if len(tagFilter.excludeSeverities) > 0 {
		_, excluded = tagFilter.excludeSeverities[templateSeverity]
	}

	return included && !excluded
}

func isAuthorMatch(tagFilter *TagFilter, templateAuthors []string) bool {
	if len(tagFilter.authors) == 0 {
		return true
	}

	templateAuthorMap := toMap(templateAuthors)
	for requiredAuthor := range tagFilter.authors {
		if _, ok := templateAuthorMap[requiredAuthor]; ok {
			return true
		}
	}

	return false
}

func isExtraTagMatch(extraTags []string, templateTags []string) bool {
	if len(extraTags) == 0 {
		return true
	}

	templatesTagMap := toMap(templateTags)
	for _, extraTag := range extraTags {
		if _, ok := templatesTagMap[extraTag]; ok {
			return true
		}
	}

	return false
}

func isTagMatch(tagFilter *TagFilter, templateTags []string) bool {
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

type Config struct {
	Tags              []string
	ExcludeTags       []string
	Authors           []string
	Severities        severity.Severities
	ExcludeSeverities severity.Severities
	IncludeTags       []string
}

// New returns a tag filter for nuclei tag based execution
//
// It takes into account Tags, Severities, ExcludeSeverities, Authors, IncludeTags, ExcludeTags.
func New(config *Config) *TagFilter {
	filter := &TagFilter{
		allowedTags:       make(map[string]struct{}),
		authors:           make(map[string]struct{}),
		severities:        make(map[severity.Severity]struct{}),
		excludeSeverities: make(map[severity.Severity]struct{}),
		block:             make(map[string]struct{}),
		matchAllows:       make(map[string]struct{}),
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
	for _, tag := range config.ExcludeSeverities {
		if _, ok := filter.excludeSeverities[tag]; !ok {
			filter.excludeSeverities[tag] = struct{}{}
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

func toMap(slice []string) map[string]struct{} {
	result := make(map[string]struct{}, len(slice))
	for _, value := range slice {
		if _, ok := result[value]; !ok {
			result[value] = struct{}{}
		}
	}
	return result
}
