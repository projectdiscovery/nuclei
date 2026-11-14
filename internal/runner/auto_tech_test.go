package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func TestDetectedTechCollectsNamesPerTarget(t *testing.T) {
	detected := newDetectedTech()
	tomcat := &contextargs.MetaInput{Input: "https://a.example"}
	detected.add(tomcat, []*output.ResultEvent{
		{TemplateID: "tomcat-detect", MatcherStatus: true, Info: model.Info{Metadata: map[string]any{"product": "tomcat"}}},
		{TemplateID: "tech-detect", MatcherName: "nginx", MatcherStatus: true},
		{TemplateID: "php-detect"},
	})
	detected.add(&contextargs.MetaInput{Input: "https://a.example"}, []*output.ResultEvent{{TemplateID: "tech-detect", MatcherName: "nginx", MatcherStatus: true}})
	detected.add(&contextargs.MetaInput{Input: "https://b.example"}, nil)

	targets := detected.targets()
	require.Len(t, targets, 1)
	require.Equal(t, []string{"nginx", "tech", "tomcat"}, targets[0].tech)
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
