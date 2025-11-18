package loader_test

import (
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

func BenchmarkStoreValidateTemplates(b *testing.B) {
	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	testutils.Init(options)

	catalog := disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Parser = templates.NewParser()

	workflowLoader, err := workflow.NewLoader(executerOpts)
	if err != nil {
		b.Fatalf("could not create workflow loader: %s", err)
	}
	executerOpts.WorkflowLoader = workflowLoader

	loaderCfg := loader.NewConfig(options, catalog, executerOpts)

	store, err := loader.New(loaderCfg)
	if err != nil {
		b.Fatalf("could not create store: %s", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_ = store.ValidateTemplates()
	}
}
