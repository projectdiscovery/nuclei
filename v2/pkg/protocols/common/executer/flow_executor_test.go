package executer_test

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

var executerOpts protocols.ExecutorOptions

func setup() {
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, false, 0)

	executerOpts = protocols.ExecutorOptions{
		Output:       testutils.NewMockOutputWriter(),
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		RateLimiter:  ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
	}
	workflowLoader, err := parsers.NewLoader(&executerOpts)
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

	gotresults, err := Template.Executer.Execute(contextargs.NewWithInput("hackerone.com"))
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)

	// apart from parse->compile->execution this testcase checks if dynamic extracted variables are available
	value, ok := Template.Options.TemplateCtx.Get("nameservers")
	require.True(t, ok)
	if value != nil {
		require.True(t, len(value.([]string)) > 0)
	}
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

	gotresults, err := Template.Executer.Execute(contextargs.NewWithInput("hackerone.com"))
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)

	value, ok := Template.Options.TemplateCtx.Get("nameservers")
	require.True(t, ok)
	if value != nil {
		require.True(t, len(value.([]string)) > 0)
	}
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

	gotresults, err := Template.Executer.Execute(contextargs.NewWithInput("hackerone.com"))
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)

	// while there are lot of variables lets just look for only these
	protoVars := []string{"dns_0_host", "dns_0_matched", "dns_0_answer", "dns_0_raw",
		"probe-ns_host", "probe-ns_matched", "probe-ns_answer", "probe-ns_raw"}

	for _, v := range protoVars {
		value, ok := Template.Options.TemplateCtx.Get(v)
		require.Truef(t, ok, "could not find variable %s", v)
		if value != nil {
			require.Truef(t, len(value.(string)) > 0, "variable %s is empty", v)
		}
	}
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

	// expect no results and verify thant dns request is executed and http is not
	gotresults, err := Template.Executer.Execute(contextargs.NewWithInput("scanme.sh"))
	require.Nil(t, err, "could not execute template")
	require.False(t, gotresults)

	m := Template.Options.TemplateCtx.GetAll()

	require.Equal(t, m["http_status"], nil) // since http() was not execute this variable should not exist
	require.NotEqual(t, m["dns_raw"], "")   // since dns() was execute this variable should exist
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

	// positive match . expect results also verify that both dns() and http() were executed
	gotresults, err := Template.Executer.Execute(contextargs.NewWithInput("blog.projectdiscovery.io"))
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)

	m := Template.Options.TemplateCtx.GetAll()

	require.NotEqual(t, m["http_status"], "") // since http() was not execute this variable should not exist
	require.NotEqual(t, m["dns_raw"], "")     // since dns() was execute this variable should exist
}
