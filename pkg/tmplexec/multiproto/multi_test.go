package multiproto_test

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

var executerOpts protocols.ExecutorOptions

func setup(t *testing.T) {
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

	dialers, err := protocols.NewDialers(options)
	require.Nil(t, err, "could not create dialers")

	executerOpts = protocols.ExecutorOptions{
		Output:       testutils.NewMockOutputWriter(options.OmitTemplate),
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		RateLimiter:  ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
		Parser:       templates.NewParser(),
		Dialers:      dialers,
	}
	workflowLoader, err := workflow.NewLoader(&executerOpts)
	require.Nil(t, err, "could not create workflow loader")
	executerOpts.WorkflowLoader = workflowLoader
}

func TestMultiProtoWithDynamicExtractor(t *testing.T) {
	setup(t)

	Template, err := templates.Parse("testcases/multiprotodynamic.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.Equal(t, 2, len(Template.RequestsQueue))

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "blog.projectdiscovery.io")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestMultiProtoWithProtoPrefix(t *testing.T) {
	setup(t)

	Template, err := templates.Parse("testcases/multiprotowithprefix.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.Equal(t, 3, len(Template.RequestsQueue))

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "blog.projectdiscovery.io")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}
