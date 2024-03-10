package filters

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	sliceutil "github.com/projectdiscovery/utils/slice"
)

// CreateIssueResponse is a response to creating an issue
// in a tracker
type CreateIssueResponse struct {
	IssueID  string `json:"issue_id"`
	IssueURL string `json:"issue_url"`
}

// Filter filters the received event and decides whether to perform
// reporting for it or not.
type Filter struct {
	Severities severity.Severities     `yaml:"severity"`
	Tags       stringslice.StringSlice `yaml:"tags"`
}

// GetMatch returns true if a filter matches result event
func (filter *Filter) GetMatch(event *output.ResultEvent) bool {
	return isSeverityMatch(event, filter) && isTagMatch(event, filter) // TODO revisit this
}

func isTagMatch(event *output.ResultEvent, filter *Filter) bool {
	filterTags := filter.Tags
	if filterTags.IsEmpty() {
		return true
	}

	tags := event.Info.Tags.ToSlice()
	for _, filterTag := range filterTags.ToSlice() {
		if sliceutil.Contains(tags, filterTag) {
			return true
		}
	}

	return false
}

func isSeverityMatch(event *output.ResultEvent, filter *Filter) bool {
	resultEventSeverity := event.Info.SeverityHolder.Severity // TODO review

	if len(filter.Severities) == 0 {
		return true
	}

	return sliceutil.Contains(filter.Severities, resultEventSeverity)
}
