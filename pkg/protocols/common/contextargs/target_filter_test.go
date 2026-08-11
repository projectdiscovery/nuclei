package contextargs

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/stretchr/testify/require"
)

func TestTargetFilterMatchesTemplate(t *testing.T) {
	filter := &TargetFilter{}
	filter.Prepare(
		[]string{"apache"},
		[]string{"deprecated"},
		severity.Severities{severity.High},
		[]string{"/templates/apache.yaml"},
		[]string{"/templates/forced.yaml"},
		true,
	)

	tests := []struct {
		name       string
		path       string
		tags       []string
		severity   severity.Severity
		isWorkflow bool
		expected   bool
	}{
		{
			name:     "matching template",
			path:     "/templates/apache.yaml",
			tags:     []string{"apache"},
			severity: severity.High,
			expected: true,
		},
		{
			name:     "template path rejected",
			path:     "/templates/other.yaml",
			tags:     []string{"apache"},
			severity: severity.High,
			expected: false,
		},
		{
			name:     "required tag missing",
			path:     "/templates/apache.yaml",
			tags:     []string{"nginx"},
			severity: severity.High,
			expected: false,
		},
		{
			name:     "excluded tag wins",
			path:     "/templates/apache.yaml",
			tags:     []string{"apache", "deprecated"},
			severity: severity.High,
			expected: false,
		},
		{
			name:     "severity rejected",
			path:     "/templates/apache.yaml",
			tags:     []string{"apache"},
			severity: severity.Low,
			expected: false,
		},
		{
			name:     "undefined severity rejected",
			path:     "/templates/apache.yaml",
			tags:     []string{"apache"},
			severity: severity.Undefined,
			expected: false,
		},
		{
			name:     "explicit include bypasses filters",
			path:     "/templates/forced.yaml",
			tags:     []string{"deprecated"},
			severity: severity.Low,
			expected: true,
		},
		{
			name:       "workflow bypasses template filters",
			path:       "/workflows/example.yaml",
			tags:       nil,
			severity:   severity.Undefined,
			isWorkflow: true,
			expected:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, filter.MatchesTemplate(test.path, test.tags, test.severity, test.isWorkflow))
		})
	}
}

func TestTargetFilterPrepareNormalizesTemplatePaths(t *testing.T) {
	filter := &TargetFilter{}
	filter.Prepare(
		nil,
		nil,
		nil,
		[]string{"/templates/zzz.yaml", "/templates/aaa.yaml", "/templates/dir/../mmm.yaml"},
		[]string{"/forced/b.yaml", "/forced/a.yaml"},
		true,
	)

	for _, path := range []string{"/templates/zzz.yaml", "/templates/aaa.yaml", "/templates/mmm.yaml"} {
		require.True(t, filter.MatchesTemplate(path, nil, severity.High, false), path)
	}
	for _, path := range []string{"/forced/a.yaml", "/forced/b.yaml"} {
		require.True(t, filter.MatchesTemplate(path, []string{"any"}, severity.Low, false), path)
	}
	require.False(t, filter.MatchesTemplate("/templates/other.yaml", nil, severity.High, false))
}

func TestTargetFilterIdentityIsCanonicalAndPresenceAware(t *testing.T) {
	omitted := &TargetFilter{}
	explicitEmpty := &TargetFilter{HasTags: true, Tags: []string{}}
	require.NotEqual(t, omitted.identity(), explicitEmpty.identity())

	first := &TargetFilter{
		HasTags:       true,
		HasSeverities: true,
		Tags:          []string{"shiro", "apache"},
		Severities:    severity.Severities{severity.High, severity.Critical},
	}
	second := &TargetFilter{
		HasTags:       true,
		HasSeverities: true,
		Tags:          []string{"apache", "shiro"},
		Severities:    severity.Severities{severity.Critical, severity.High},
	}
	first.Prepare(first.Tags, nil, first.Severities, nil, nil, false)
	second.Prepare(second.Tags, nil, second.Severities, nil, nil, false)
	require.Equal(t, first.identity(), second.identity())
}

func TestTargetFilterCloneSharesOnlyImmutablePreparedState(t *testing.T) {
	original := &TargetFilter{
		HasTags: true,
		Tags:    []string{"apache"},
	}
	original.Prepare(original.Tags, []string{"deprecated"}, severity.Severities{severity.High}, []string{"/one.yaml"}, []string{"/forced.yaml"}, true)

	cloned := original.clone()
	cloned.Tags[0] = "nginx"

	require.Equal(t, []string{"apache"}, original.Tags)
	require.Same(t, original.prepared, cloned.prepared)
	require.True(t, cloned.MatchesTemplate("/one.yaml", []string{"apache"}, severity.High, false))
	require.False(t, cloned.MatchesTemplate("/one.yaml", []string{"nginx"}, severity.High, false))
	require.Equal(t, original.identity(), cloned.identity())
}
