package nucleicloud

import (
	"encoding/json"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

// AddScanRequest is a nuclei scan input item.
type AddScanRequest struct {
	// RawTargets is a list of raw target URLs for the scan.
	RawTargets []string `json:"raw_targets,omitempty"`
	// PublicTemplates is a list of public templates for the scan
	PublicTemplates []string `json:"public_templates,omitempty"`
	// PrivateTemplates is a map of template-name->contents that
	// are private to the user executing the scan. (TODO: TBD)
	PrivateTemplates map[string]string `json:"private_templates,omitempty"`
	// CloudTargets is a list of cloud targets for the scan
	CloudTargets []string `json:"cloud_targets,omitempty"`
	// CloudTemplates is a list of cloud templates for the scan
	CloudTemplates []string `json:"cloud_templates,omitempty"`
	// Filtering contains optional filtering options for scan additions
	Filtering *AddScanRequestConfiguration `json:"filtering"`

	IsTemporary bool `json:"is_temporary"`
}

// AddScanRequestConfiguration contains filtering options for scan addition
type AddScanRequestConfiguration struct {
	Authors           []string            `json:"author,omitempty"`
	Tags              []string            `json:"tags,omitempty"`
	ExcludeTags       []string            `json:"exclude-tags,omitempty"`
	IncludeTags       []string            `json:"include-tags,omitempty"`
	IncludeIds        []string            `json:"include-ids,omitempty"`
	ExcludeIds        []string            `json:"exclude-ids,omitempty"`
	IncludeTemplates  []string            `json:"include-templates,omitempty"`
	ExcludedTemplates []string            `json:"exclude-templates,omitempty"`
	ExcludeMatchers   []string            `json:"exclude-matchers,omitempty"`
	Severities        severity.Severities `json:"severities,omitempty"`
	ExcludeSeverities severity.Severities `json:"exclude-severities,omitempty"`
	Protocols         types.ProtocolTypes `json:"protocols,omitempty"`
	ExcludeProtocols  types.ProtocolTypes `json:"exclude-protocols,omitempty"`
	IncludeConditions []string            `json:"include-conditions,omitempty"`
}

type GetResultsResponse struct {
	Finished bool                     `json:"finished"`
	Items    []GetResultsResponseItem `json:"items"`
}

type GetScanRequest struct {
	Id         int64     `json:"id"`
	Total      int32     `json:"total"`
	Current    int32     `json:"current"`
	Finished   bool      `json:"finished"`
	CreatedAt  time.Time `json:"created_at"`
	FinishedAt time.Time `json:"finished_at"`
	Targets    int32     `json:"targets"`
	Templates  int32     `json:"templates"`
	Matches    int64     `json:"matches"`
}

// AddDataSourceResponse is a add data source response item.
type AddDataSourceResponse struct {
	ID     int64  `json:"id"`
	Hash   string `json:"hash"`
	Secret string `json:"secret,omitempty"`
}

type GetResultsResponseItem struct {
	ID  int64  `json:"id"`
	Raw string `json:"raw"`
}

type DeleteScanResults struct {
	OK bool `json:"ok"`
}

// StatusDataSourceRequest is a add data source request item.
type StatusDataSourceRequest struct {
	Repo  string `json:"repo"`
	Token string `json:"token"`
}

// StatusDataSourceResponse is a add data source response item.
type StatusDataSourceResponse struct {
	ID int64 `json:"id"`
}

// AddDataSourceRequest is a add data source request item.
type AddDataSourceRequest struct {
	Type  string `json:"type"`
	Repo  string `json:"repo"`
	Token string `json:"token"`
	Sync  bool   `json:"sync"`
}

// ExistsDataSourceItemRequest is a request to identify whether a data
// source item exists.
type ExistsDataSourceItemRequest struct {
	Type     string `json:"type"`
	Contents string `json:"contents"`
}

// GetDataSourceResponse is response for a get data source request
type GetDataSourceResponse struct {
	ID        int64     `json:"id"`
	Hash      string    `json:"hash"`
	Type      string    `json:"type"`
	Path      string    `json:"path"`
	Repo      string    `json:"repo"`
	Updatedat time.Time `json:"updated_at"`
}

// GetTargetResponse is the response for a get target request
type GetTargetResponse struct {
	ID         int64  `json:"id"`
	DataSource int64  `json:"data_source"`
	Name       string `json:"name"`
	Reference  string `json:"reference"`
	Count      int64  `json:"count"`
	Hash       string `json:"hash"`
	Type       string `json:"type"`
}

// GetTemplatesResponse is the response for a get templates request
type GetTemplatesResponse struct {
	ID         int64  `json:"id,omitempty"`
	DataSource int64  `json:"data_source,omitempty"`
	Name       string `json:"name,omitempty"`
	Reference  string `json:"reference,omitempty"`
	Hash       string `json:"hash,omitempty"`
	Type       string `json:"type,omitempty"`
}

type GetReportingSourceResponse struct {
	ID          int64     `json:"id"`
	Type        string    `json:"type"`
	ProjectName string    `json:"project_name"`
	Enabled     bool      `json:"enabled"`
	Updatedat   time.Time `json:"updated_at"`
}

type ReportingSourceStatus struct {
	Enabled bool `json:"enabled"`
}

// AddItemResponse is the response to add item request
type AddItemResponse struct {
	Ok string `json:"ok"`
}

type ListScanOutput struct {
	Timestamp  string `json:"timestamp"`
	ScanID     int64  `json:"scan_id"`
	ScanTime   string `json:"scan_time"`
	ScanResult int    `json:"scan_result"`
	ScanStatus string `json:"scan_status"`
	Target     int    `json:"target"`
	Template   int    `json:"template"`
}

type ExistsInputResponse struct {
	Reference string `json:"reference"`
}

// AddReportingSourceRequest is a add reporting source request item.
type AddReportingSourceRequest struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// AddReportingSourceResponse is a add reporting source response item.
type AddReportingSourceResponse struct {
	Ok string `json:"ok"`
}
