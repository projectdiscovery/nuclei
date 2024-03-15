package parser

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
)

type Parser interface {
	LoadTemplate(templatePath string, tagFilter any, extraTags []string, catalog catalog.Catalog) (bool, error)
	ParseTemplate(templatePath string, catalog catalog.Catalog) (any, error)
	LoadWorkflow(templatePath string, catalog catalog.Catalog) (bool, error)
}
