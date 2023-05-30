package templates_test

import (
	"context"
	"fmt"
	"log"
	netHttp "net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/variables"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
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

func Test_ParseFromURL(t *testing.T) {
	router := httprouter.New()
	router.GET("/match-1.yaml", func(w netHttp.ResponseWriter, r *netHttp.Request, _ httprouter.Params) {
		b, err := os.ReadFile("tests/match-1.yaml")
		if err != nil {
			w.Write([]byte(err.Error())) // nolint: errcheck
		}
		w.Write(b) // nolint: errcheck
	})
	ts := httptest.NewServer(router)
	defer ts.Close()
	var expectedTemplate = &templates.Template{
		ID: "basic-get",
		Info: model.Info{
			Name:           "Basic GET Request",
			Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		RequestsHTTP: []*http.Request{{
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type: matchers.MatcherTypeHolder{
						MatcherType: matchers.WordsMatcher,
					},
					Words: []string{"This is test matcher text"},
				}},
			},
			Path:       []string{"{{BaseURL}}"},
			AttackType: generators.AttackTypeHolder{},
			Method: http.HTTPMethodTypeHolder{
				MethodType: http.HTTPGet,
			},
		}},
		TotalRequests: 1,
		Executer:      nil,
		Path:          ts.URL + "/match-1.yaml",
	}
	setup()
	got, err := templates.Parse(ts.URL+"/match-1.yaml", nil, executerOpts)
	require.Nilf(t, err, "could not parse template (%s)", fmt.Sprint(err))
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
	require.Equal(t, expectedTemplate.Info, got.Info)
	require.Equal(t, expectedTemplate.TotalRequests, got.TotalRequests)
	require.Equal(t, expectedTemplate.Path, got.Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Path, got.RequestsHTTP[0].Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Operators.Matchers[0].Words, got.RequestsHTTP[0].Operators.Matchers[0].Words)
	require.Equal(t, len(expectedTemplate.RequestsHTTP), len(got.RequestsHTTP))
}

func Test_ParseFromFile(t *testing.T) {
	filePath := "tests/match-1.yaml"
	expectedTemplate := &templates.Template{
		ID: "basic-get",
		Info: model.Info{
			Name:           "Basic GET Request",
			Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		RequestsHTTP: []*http.Request{{
			Operators: operators.Operators{
				Matchers: []*matchers.Matcher{{
					Type: matchers.MatcherTypeHolder{
						MatcherType: matchers.WordsMatcher,
					},
					Words: []string{"This is test matcher text"},
				}},
			},
			Path:       []string{"{{BaseURL}}"},
			AttackType: generators.AttackTypeHolder{},
			Method: http.HTTPMethodTypeHolder{
				MethodType: http.HTTPGet,
			},
		}},
		TotalRequests: 1,
		Executer:      nil,
		Path:          "tests/match-1.yaml",
	}
	setup()
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
	require.Equal(t, expectedTemplate.Info, got.Info)
	require.Equal(t, expectedTemplate.TotalRequests, got.TotalRequests)
	require.Equal(t, expectedTemplate.Path, got.Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Path, got.RequestsHTTP[0].Path)
	require.Equal(t, expectedTemplate.RequestsHTTP[0].Operators.Matchers[0].Words, got.RequestsHTTP[0].Operators.Matchers[0].Words)
	require.Equal(t, len(expectedTemplate.RequestsHTTP), len(got.RequestsHTTP))

	// Test cache
	got, err = templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
}

func Test_ParseWorkflow(t *testing.T) {
	filePath := "tests/workflow.yaml"
	expectedTemplate := &templates.Template{
		ID: "workflow-example",
		Info: model.Info{
			Name:           "Test Workflow Template",
			Authors:        stringslice.StringSlice{Value: []string{"pdteam"}},
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		Workflow: workflows.Workflow{
			Workflows: []*workflows.WorkflowTemplate{{Template: "tests/match-1.yaml"}, {Template: "tests/match-1.yaml"}},
			Options:   &protocols.ExecutorOptions{},
		},
		CompiledWorkflow: &workflows.Workflow{},
		SelfContained:    false,
		StopAtFirstMatch: false,
		Signature:        http.SignatureTypeHolder{},
		Variables:        variables.Variable{},
		TotalRequests:    0,
		Executer:         nil,
		Path:             "tests/workflow.yaml",
	}
	setup()
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, err, "could not parse template")
	require.Equal(t, expectedTemplate.ID, got.ID)
	require.Equal(t, expectedTemplate.Info, got.Info)
	require.Equal(t, expectedTemplate.TotalRequests, got.TotalRequests)
	require.Equal(t, expectedTemplate.Path, got.Path)
	require.Equal(t, expectedTemplate.Workflow.Workflows[0].Template, got.Workflow.Workflows[0].Template)
	require.Equal(t, len(expectedTemplate.Workflows), len(got.Workflows))
}

func Test_WrongTemplate(t *testing.T) {
	setup()

	filePath := "tests/no-author.yaml"
	got, err := templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, got, "could not parse template")
	require.ErrorContains(t, err, "no template author field provided")

	filePath = "tests/no-req.yaml"
	got, err = templates.Parse(filePath, nil, executerOpts)
	require.Nil(t, got, "could not parse template")
	require.ErrorContains(t, err, "no requests defined ")
}
