package reporting

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Client is a client for nuclei issue tracking module
type Client interface {
	RegisterTracker(tracker Tracker)
	RegisterExporter(exporter Exporter)
	Close()
	Clear()
	CreateIssue(event *output.ResultEvent) error
	CloseIssue(event *output.ResultEvent) error
	GetReportingOptions() *Options
}
