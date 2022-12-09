package nucleicloud

import (
	"time"
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

	IsTemporary bool `json:"is_temporary"`
}

type GetResultsResponse struct {
	Finished bool                     `json:"finished"`
	Items    []GetResultsResponseItem `json:"items"`
}

type GetScanRequest struct {
	Id         string    `json:"id"`
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
	ID        int64  `json:"id"`
	Reference string `json:"reference"`
}

// GetTemplatesResponse is the response for a get templates request
type GetTemplatesResponse struct {
	ID        int64  `json:"id"`
	Reference string `json:"reference"`
}

// AddItemResponse is the response to add item request
type AddItemResponse struct {
	Ok string `json:"ok"`
}
