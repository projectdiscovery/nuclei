package loader_test

import (
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
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

func BenchmarkLoadTemplates(b *testing.B) {
	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	options.ExecutionId = "bench-load-templates"
	testutils.Init(options)

	catalog := disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Parser = templates.NewParser()

	workflowLoader, err := workflow.NewLoader(executerOpts)
	if err != nil {
		b.Fatalf("could not create workflow loader: %s", err)
	}
	executerOpts.WorkflowLoader = workflowLoader

	b.Run("NoFilter", func(b *testing.B) {
		loaderCfg := loader.NewConfig(options, catalog, executerOpts)
		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		}
	})

	b.Run("FilterBySeverityCritical", func(b *testing.B) {
		opts := options.Copy()
		opts.Severities = severity.Severities{severity.Critical}
		loaderCfg := loader.NewConfig(opts, catalog, executerOpts)

		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		}
	})

	b.Run("FilterBySeverityHighCritical", func(b *testing.B) {
		opts := options.Copy()
		opts.Severities = severity.Severities{severity.High, severity.Critical}
		loaderCfg := loader.NewConfig(opts, catalog, executerOpts)

		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		}
	})

	b.Run("FilterByAuthor", func(b *testing.B) {
		opts := options.Copy()
		opts.Authors = []string{"pdteam"}
		loaderCfg := loader.NewConfig(opts, catalog, executerOpts)

		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		}
	})

	b.Run("FilterByTags", func(b *testing.B) {
		opts := options.Copy()
		opts.Tags = []string{"cve", "rce"}
		loaderCfg := loader.NewConfig(opts, catalog, executerOpts)

		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		}
	})

	b.Run("FilterByProtocol", func(b *testing.B) {
		opts := options.Copy()
		opts.Protocols = templateTypes.ProtocolTypes{templateTypes.HTTPProtocol}
		loaderCfg := loader.NewConfig(opts, catalog, executerOpts)

		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		}
	})

	b.Run("ComplexFilter", func(b *testing.B) {
		opts := options.Copy()
		opts.Severities = severity.Severities{severity.High, severity.Critical}
		opts.Authors = []string{"pdteam"}
		opts.Tags = []string{"cve"}
		loaderCfg := loader.NewConfig(opts, catalog, executerOpts)

		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplates([]string{config.DefaultConfig.TemplatesDirectory})
		}
	})
}

func BenchmarkLoadTemplatesOnlyMetadata(b *testing.B) {
	options := testutils.DefaultOptions.Copy()
	options.Logger = &gologger.Logger{}
	options.ExecutionId = "bench-metadata"
	testutils.Init(options)

	catalog := disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)
	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Parser = templates.NewParser()

	workflowLoader, err := workflow.NewLoader(executerOpts)
	if err != nil {
		b.Fatalf("could not create workflow loader: %s", err)
	}
	executerOpts.WorkflowLoader = workflowLoader

	b.Run("WithoutFilter", func(b *testing.B) {
		loaderCfg := loader.NewConfig(options, catalog, executerOpts)
		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		// Pre-warm the cache
		_ = store.LoadTemplatesOnlyMetadata()

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplatesOnlyMetadata()
		}
	})

	b.Run("WithSeverityFilter", func(b *testing.B) {
		opts := options.Copy()
		opts.Severities = severity.Severities{severity.Critical}
		loaderCfg := loader.NewConfig(opts, catalog, executerOpts)

		store, err := loader.New(loaderCfg)
		if err != nil {
			b.Fatalf("could not create store: %s", err)
		}

		// Pre-warm the cache
		_ = store.LoadTemplatesOnlyMetadata()

		b.ResetTimer()
		b.ReportAllocs()

		for b.Loop() {
			_ = store.LoadTemplatesOnlyMetadata()
		}
	})
}
