package templates

import (
	"slices"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

type allowList struct{ paths []string }

func (a *allowList) Allows(templatePath string) bool { return slices.Contains(a.paths, templatePath) }

type scopeByInput map[string]*allowList

func (s scopeByInput) For(input *contextargs.MetaInput) protocols.TemplateSelection {
	if selection, ok := s[input.Input]; ok {
		return selection
	}
	return nil
}

func TestClusterMembersFollowTargetScope(t *testing.T) {
	cluster := &ClusterExecuter{
		operators: []*clusteredOperator{
			{templateID: "thinkphp", templatePath: "thinkphp.yaml"},
			{templateID: "tomcat", templatePath: "tomcat.yaml"},
		},
		options: &protocols.ExecutorOptions{TargetScope: scopeByInput{
			"php":  {paths: []string{"thinkphp.yaml"}},
			"none": {},
		}},
	}
	clustered := &Template{ID: "cluster-x", Executer: cluster}

	memberIDs := func(input string) []string {
		var ids []string
		for _, operator := range cluster.operatorsFor(&contextargs.MetaInput{Input: input}) {
			ids = append(ids, operator.templateID)
		}
		return ids
	}

	require.Equal(t, []string{"thinkphp"}, memberIDs("php"))
	require.Empty(t, memberIDs("none"))
	require.Equal(t, []string{"thinkphp", "tomcat"}, memberIDs("plain"))
	require.Len(t, cluster.operators, 2, "filtering must not mutate the shared member list")

	require.True(t, clustered.SelectedBy(&allowList{paths: []string{"tomcat.yaml"}}))
	require.False(t, clustered.SelectedBy(&allowList{}))
	require.True(t, (&Template{Path: "a.yaml"}).SelectedBy(&allowList{paths: []string{"a.yaml"}}))
}
