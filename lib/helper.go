package nuclei

import (
	"context"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	uncoverNuclei "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/uncover"
)

// helper.go file proxy execution of all nuclei functions that are nested deep inside multiple packages
// but are helpful / useful while using nuclei as a library

// GetTargetsFromUncover returns targets from uncover in given format .
// supported formats are any string with [ip,host,port,url] placeholders
func GetTargetsFromUncover(ctx context.Context, outputFormat string, opts *uncover.Options) (chan string, error) {
	return uncoverNuclei.GetTargetsFromUncover(ctx, outputFormat, opts)
}

// GetTargetsFromTemplateMetadata returns all targets by querying engine metadata (ex: fofo-query,shodan-query) etc from given templates .
// supported formats are any string with [ip,host,port,url] placeholders
func GetTargetsFromTemplateMetadata(ctx context.Context, templates []*templates.Template, outputFormat string, opts *uncover.Options) chan string {
	return uncoverNuclei.GetUncoverTargetsFromMetadata(ctx, templates, outputFormat, opts)
}

// DefaultConfig is instance of default nuclei configs
// any mutations to this config will be reflected in all nuclei instances (saves some config to disk)
var DefaultConfig *config.Config

func init() {
	DefaultConfig = config.DefaultConfig
}
