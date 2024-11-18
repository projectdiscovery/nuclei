package flow_test

import (
	"context"
	"log"
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

func setup() {
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

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
	}
	workflowLoader, err := workflow.NewLoader(&executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader
}

func TestFlowTemplateWithIndex(t *testing.T) {
	// test
	setup()
	Template, err := templates.Parse("testcases/nuclei-flow-dns.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "hackerone.com")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowTemplateWithID(t *testing.T) {
	setup()
	// apart from parse->compile->execution this testcase checks support for use custom id for protocol request and invocation of
	// the same in js
	Template, err := templates.Parse("testcases/nuclei-flow-dns-id.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	target := contextargs.NewWithInput(context.Background(), "hackerone.com")
	ctx := scan.NewScanContext(context.Background(), target)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowWithProtoPrefix(t *testing.T) {
	// test
	setup()

	// apart from parse->compile->execution this testcase checks
	// mix of custom protocol request id and index is supported in js
	// and also validates availability of protocol response variables in template context
	Template, err := templates.Parse("testcases/nuclei-flow-dns-prefix.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "hackerone.com")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowWithConditionNegative(t *testing.T) {
	setup()

	// apart from parse->compile->execution this testcase checks
	// if bitwise operator (&&) are properly executed and working
	Template, err := templates.Parse("testcases/condition-flow.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "scanme.sh")
	ctx := scan.NewScanContext(context.Background(), input)
	// expect no results and verify thant dns request is executed and http is not
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.False(t, gotresults)
}

func TestFlowWithConditionPositive(t *testing.T) {
	setup()

	// apart from parse->compile->execution this testcase checks
	// if bitwise operator (&&) are properly executed and working
	Template, err := templates.Parse("testcases/condition-flow.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "cloud.projectdiscovery.io")
	ctx := scan.NewScanContext(context.Background(), input)
	// positive match . expect results also verify that both dns() and http() were executed
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestFlowWithNoMatchers(t *testing.T) {
	setup()
	// when using conditional flow with no matchers at all
	// we implicitly assume that request was successful and internally changed the result to true (for scope of condition only)

	Template, err := templates.Parse("testcases/condition-flow-no-operators.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	anotherInput := contextargs.NewWithInput(context.Background(), "cloud.projectdiscovery.io")
	anotherCtx := scan.NewScanContext(context.Background(), anotherInput)
	// positive match . expect results also verify that both dns() and http() were executed
	gotresults, err := Template.Executer.Execute(anotherCtx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)

	t.Run("Contains Extractor", func(t *testing.T) {
		Template, err := templates.Parse("testcases/condition-flow-extractors.yaml", nil, executerOpts)
		require.Nil(t, err, "could not parse template")

		require.True(t, Template.Flow != "", "not a flow template") // this is classifer if template is flow or not

		err = Template.Executer.Compile()
		require.Nil(t, err, "could not compile template")

		input := contextargs.NewWithInput(context.Background(), "scanme.sh")
		ctx := scan.NewScanContext(context.Background(), input)
		// positive match . expect results also verify that both dns() and http() were executed
		gotresults, err := Template.Executer.Execute(ctx)
		require.Nil(t, err, "could not execute template")
		require.True(t, gotresults)
	})
}
