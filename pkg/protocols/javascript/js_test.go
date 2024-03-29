package javascript_test

import (
	"log"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/cruisecontrol"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/stretchr/testify/require"
)

var (
	testcases = []string{
		"testcases/ms-sql-detect.yaml",
		"testcases/redis-pass-brute.yaml",
		"testcases/ssh-server-fingerprint.yaml",
	}
	executerOpts protocols.ExecutorOptions
)

func setup() {
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

	cruiseControl, _ := cruisecontrol.New(cruisecontrol.ParseOptionsFrom(options))
	httpClientPool, _ := httpclientpool.New(options)

	executerOpts = protocols.ExecutorOptions{
		Output:         testutils.NewMockOutputWriter(options.OmitTemplate),
		Options:        options,
		Progress:       progressImpl,
		ProjectFile:    nil,
		IssuesClient:   nil,
		Browser:        nil,
		Catalog:        disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		CruiseControl:  cruiseControl,
		HttpClientPool: httpClientPool,
		Parser:         templates.NewParser(),
	}
	workflowLoader, err := workflow.NewLoader(&executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader
}

func TestCompile(t *testing.T) {
	setup()
	for index, tpl := range testcases {
		// parse template
		template, err := templates.Parse(tpl, nil, executerOpts)
		require.Nilf(t, err, "failed to parse %v", tpl)

		// compile template
		err = template.Executer.Compile()
		require.Nilf(t, err, "failed to compile %v", tpl)

		switch index {
		case 0:
			// requests count should be 1
			require.Equal(t, 1, template.TotalRequests, "template : %v", tpl)
		case 1:
			// requests count should be 6 i.e 5 generator payloads + 1 precondition request
			require.Equal(t, 5+1, template.TotalRequests, "template : %v", tpl)
		case 2:
			// requests count should be 1
			require.Equal(t, 1, template.TotalRequests, "template : %v", tpl)
		}
	}
}
