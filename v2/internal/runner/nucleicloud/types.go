package nucleicloud

import "github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"

// AddScanRequest is a nuclei scan input item.
type AddScanRequest struct {
	// RawTargets is a list of raw target URLs for the scan.
	RawTargets []*contextargs.MetaInput `json:"raw_targets,omitempty"`
	// PublicTemplates is a list of public templates for the scan
	PublicTemplates []string `json:"public_templates,omitempty"`
	// PrivateTemplates is a map of template-name->contents that
	// are private to the user executing the scan. (TODO: TBD)
	PrivateTemplates map[string]string `json:"private_templates,omitempty"`
}

type GetResultsResponse struct {
	Finished bool                     `json:"finished"`
	Items    []GetResultsResponseItem `json:"items"`
}

type GetResultsResponseItem struct {
	ID  int64  `json:"id"`
	Raw string `json:"raw"`
}
