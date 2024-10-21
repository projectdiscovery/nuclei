package reporting

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/es"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/jsonexporter"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/jsonl"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/mongo"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/splunk"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/gitea"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/github"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/gitlab"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/jira"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/linear"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Options is a configuration file for nuclei reporting module
type Options struct {
	// AllowList contains a list of allowed events for reporting module
	AllowList *filters.Filter `yaml:"allow-list"`
	// DenyList contains a list of denied events for reporting module
	DenyList *filters.Filter `yaml:"deny-list"`
	// GitHub contains configuration options for GitHub Issue Tracker
	GitHub *github.Options `yaml:"github"`
	// GitLab contains configuration options for GitLab Issue Tracker
	GitLab *gitlab.Options `yaml:"gitlab"`
	// Gitea contains configuration options for Gitea Issue Tracker
	Gitea *gitea.Options `yaml:"gitea"`
	// Jira contains configuration options for Jira Issue Tracker
	Jira *jira.Options `yaml:"jira"`
	// Linear contains configuration options for Linear Issue Tracker
	Linear *linear.Options `yaml:"linear"`
	// MarkdownExporter contains configuration options for Markdown Exporter Module
	MarkdownExporter *markdown.Options `yaml:"markdown"`
	// SarifExporter contains configuration options for Sarif Exporter Module
	SarifExporter *sarif.Options `yaml:"sarif"`
	// ElasticsearchExporter contains configuration options for Elasticsearch Exporter Module
	ElasticsearchExporter *es.Options `yaml:"elasticsearch"`
	// SplunkExporter contains configuration options for splunkhec Exporter Module
	SplunkExporter *splunk.Options `yaml:"splunkhec"`
	// JSONExporter contains configuration options for JSON Exporter Module
	JSONExporter *jsonexporter.Options `yaml:"json"`
	// JSONLExporter contains configuration options for JSONL Exporter Module
	JSONLExporter *jsonl.Options `yaml:"jsonl"`
	// MongoDBExporter containers the configuration options for the MongoDB Exporter Module
	MongoDBExporter *mongo.Options `yaml:"mongodb"`

	HttpClient *retryablehttp.Client `yaml:"-"`
	OmitRaw    bool                  `yaml:"-"`
}
