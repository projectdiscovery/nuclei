package runner

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/stretchr/testify/require"
)

// profileScope selects by path, like per-target profiles do.
type profileScope struct{ sel *profileSelection }

func (p profileScope) For(*contextargs.MetaInput) protocols.TemplateSelection { return p.sel }

type profileSelection struct{ allowed map[string]bool }

func (p *profileSelection) Allows(path string) bool { return p.allowed[path] }

func TestPlanScope(t *testing.T) {
	web := &templates.Template{ID: "web", Path: "/t/web.yaml"}
	net := &templates.Template{ID: "net", Path: "/t/net.yaml"}
	dupA := &templates.Template{ID: "dup-a", Path: "/t/dup.yaml"}
	dupB := &templates.Template{ID: "dup-b", Path: "/t/dup.yaml"}
	// the filter drops the network template on host-a only
	allow := func(tpl *templates.Template, mi *contextargs.MetaInput) bool {
		return !(mi.Input == "host-a" && tpl.ID != "web")
	}
	input := func(raw string) *contextargs.MetaInput {
		mi := contextargs.NewMetaInput()
		mi.Input = raw
		return mi
	}
	a, b := input("host-a"), input("host-b")

	scope := newPlanScope(nil, allow, []*templates.Template{web, net, dupA, dupB})
	selA := scope.For(a)
	require.Same(t, selA, scope.For(input("host-a")), "one selection per target, so the engine can group targets")
	require.True(t, web.SelectedBy(selA))
	require.False(t, net.SelectedBy(selA))
	require.True(t, dupA.SelectedBy(selA), "a path shared by several templates is never filtered")
	require.True(t, net.SelectedBy(scope.For(b)))
	require.True(t, (&templates.Template{Path: "/t/unknown.yaml"}).SelectedBy(selA), "unknown templates are never filtered")

	// The plan narrows the profiles, never widens them.
	profiles := profileScope{sel: &profileSelection{allowed: map[string]bool{"/t/net.yaml": true}}}
	scope = newPlanScope(profiles, allow, []*templates.Template{web, net})
	require.False(t, web.SelectedBy(scope.For(b)), "a template the profile leaves out stays out")
	require.True(t, net.SelectedBy(scope.For(b)))
	require.False(t, net.SelectedBy(scope.For(a)))
}
