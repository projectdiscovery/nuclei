package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	httpprotocol "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/require"
)

func TestDetectedTechCollectsNamesPerTarget(t *testing.T) {
	rootDetect := &templates.Template{ID: "root-detect", RequestsHTTP: []*httpprotocol.Request{{Path: []string{"{{RootURL}}/"}}}}
	detected := newDetectedTech([]*templates.Template{rootDetect})
	detected.add(metaInput("https://a.example/app"), []*output.ResultEvent{
		{TemplateID: "tomcat-detect", MatcherStatus: true, Info: model.Info{Metadata: map[string]any{"product": "tomcat"}}},
		{TemplateID: "tech-detect", MatcherName: "nginx", MatcherStatus: true},
		{TemplateID: "php-detect"},
	})
	detected.add(metaInput("https://a.example/app"), []*output.ResultEvent{{TemplateID: "tech-detect", MatcherName: "nginx", MatcherStatus: true}})
	// run once for the origin, on whichever target claimed it
	detected.add(metaInput("https://a.example/app"), []*output.ResultEvent{{TemplateID: "root-detect", MatcherName: "jetty", MatcherStatus: true}})

	require.Equal(t, []string{"jetty", "nginx", "root", "tech", "tomcat"}, detected.of(metaInput("https://a.example/app")))
	require.Equal(t, []string{"jetty", "root"}, detected.of(metaInput("https://a.example/other")), "a sibling gets what its origin showed")
	require.Empty(t, detected.of(metaInput("https://b.example")))
}

func metaInput(target string) *contextargs.MetaInput {
	return &contextargs.MetaInput{Input: target}
}

type recordedProgress struct {
	progress.Progress
	templates int
	total     int64
	inits     int
	tasks     int64
}

func (p *recordedProgress) Init(hostCount int64, rulesCount int, requestCount int64) {
	p.inits++
	p.templates = rulesCount
	p.total = requestCount
}
func (p *recordedProgress) AddToTotal(delta int64)     { p.total += delta }
func (p *recordedProgress) AddToTaskTotal(delta int64) { p.tasks += delta }
func (p *recordedProgress) IncrementTasksBy(int64)     {}

func TestSharedRunProgressStartsOnce(t *testing.T) {
	recorded := &recordedProgress{}
	shared := &sharedRunProgress{Progress: recorded, templates: 10}
	shared.Init(2, 3, 40)
	shared.AddToTaskTotal(6)
	shared.Init(2, 7, 25)
	shared.AddToTaskTotal(4)
	require.Equal(t, 1, recorded.inits)
	require.Equal(t, 10, recorded.templates)
	require.EqualValues(t, 65, recorded.total)
	require.EqualValues(t, 10, recorded.tasks, "task counts reach the tracker")
}
