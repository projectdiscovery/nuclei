package core

import (
	"context"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
	"github.com/stretchr/testify/require"
)

// runMatcherExtractWorkflow runs a workflow whose only step matches through a
// workflow matcher and produces the given extracts, so the subtemplate started
// by that matcher resolves them like any other workflow step.
func runMatcherExtractWorkflow(t *testing.T, extracts map[string][]string, matcherName string, childHook func(ctx *scan.ScanContext, childOptions *protocols.ExecutorOptions)) bool {
	t.Helper()

	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)
	childOptions := &protocols.ExecutorOptions{TemplateID: "child-template", Progress: progressBar}
	childExecuter := &mockExecuter{result: true}
	if childHook != nil {
		childExecuter.executeScanHook = func(ctx *scan.ScanContext) {
			childHook(ctx, childOptions)
		}
	}

	workflow := &workflows.Workflow{
		Options: &protocols.ExecutorOptions{Options: &types.Options{TemplateThreads: 10}},
		Workflows: []*workflows.WorkflowTemplate{{
			Executers: []*workflows.ProtocolExecuterPair{{
				Executer: &mockExecuter{result: true, outputs: []*output.InternalWrappedEvent{{
					OperatorsResult: &operators.Result{
						Matches:  map[string][]string{"tomcat": {}},
						Extracts: extracts,
					},
					Results: []*output.ResultEvent{{}},
				}}},
				Options: &protocols.ExecutorOptions{TemplateID: "parent-template", Progress: progressBar},
			}},
			Matchers: []*workflows.Matcher{{
				Name: stringslice.StringSlice{Value: matcherName},
				Subtemplates: []*workflows.WorkflowTemplate{{
					Executers: []*workflows.ProtocolExecuterPair{{
						Executer: childExecuter,
						Options:  childOptions,
					}},
				}},
			}},
		}},
	}

	engine := &Engine{}
	input := contextargs.NewWithInput(context.Background(), "https://test.com")
	ctx := scan.NewScanContext(context.Background(), input)
	return engine.executeWorkflow(ctx, workflow)
}

// TestWorkflowsMatcherSubtemplatesExtractSingleValue covers the common workflow
// shape whose step declares matchers and extractors: the subtemplate must
// resolve the extracted value as a scalar, not as a one element list.
func TestWorkflowsMatcherSubtemplatesExtractSingleValue(t *testing.T) {
	var childWhoami interface{}
	var childRan bool

	matched := runMatcherExtractWorkflow(t, map[string][]string{"whoami": {"foo"}}, "tomcat", func(ctx *scan.ScanContext, childOptions *protocols.ExecutorOptions) {
		childRan = true
		childWhoami, _ = childOptions.GetTemplateCtx(ctx.Input.MetaInput).Get("whoami")
	})

	require.True(t, matched, "could not get correct match value")
	require.True(t, childRan, "matcher subtemplate should run when the matcher matches")
	require.Equal(t, "foo", childWhoami, "matcher subtemplate should resolve a single extract as a scalar")
}

// TestWorkflowsMatcherSubtemplatesExtractMultipleValues keeps the indexed and
// the full slice forms available for extractors returning several values.
func TestWorkflowsMatcherSubtemplatesExtractMultipleValues(t *testing.T) {
	var childPaths0, childPaths1, childPaths interface{}

	matched := runMatcherExtractWorkflow(t, map[string][]string{"paths": {"a", "b"}}, "tomcat", func(ctx *scan.ScanContext, childOptions *protocols.ExecutorOptions) {
		templateCtx := childOptions.GetTemplateCtx(ctx.Input.MetaInput)
		childPaths0, _ = templateCtx.Get("paths0")
		childPaths1, _ = templateCtx.Get("paths1")
		childPaths, _ = templateCtx.Get("paths")
	})

	require.True(t, matched, "could not get correct match value")
	require.Equal(t, "a", childPaths0, "could not index the first extracted value")
	require.Equal(t, "b", childPaths1, "could not index the second extracted value")
	require.Equal(t, []string{"a", "b"}, childPaths, "could not keep the full slice of extracted values")
}

// TestWorkflowsMatcherSubtemplatesWithoutExtracts covers steps that extract
// nothing at all: the subtemplate still runs and no value is invented.
func TestWorkflowsMatcherSubtemplatesWithoutExtracts(t *testing.T) {
	var childRan bool
	var childWhoami interface{}

	matched := runMatcherExtractWorkflow(t, map[string][]string{}, "tomcat", func(ctx *scan.ScanContext, childOptions *protocols.ExecutorOptions) {
		childRan = true
		childWhoami, _ = childOptions.GetTemplateCtx(ctx.Input.MetaInput).Get("whoami")
	})

	require.True(t, matched, "could not get correct match value")
	require.True(t, childRan, "matcher subtemplate should run when the matcher matches")
	require.Nil(t, childWhoami, "no extract should be propagated for a step without extracts")
}

// TestWorkflowsMatcherSubtemplatesEmptyExtractValue covers an extractor that
// produced no value: the subtemplate runs and nothing is set, instead of
// indexing the empty slice.
func TestWorkflowsMatcherSubtemplatesEmptyExtractValue(t *testing.T) {
	var childRan bool
	var childWhoami interface{}
	var childWhoamiSet bool

	matched := runMatcherExtractWorkflow(t, map[string][]string{"whoami": {}}, "tomcat", func(ctx *scan.ScanContext, childOptions *protocols.ExecutorOptions) {
		childRan = true
		childWhoami, childWhoamiSet = childOptions.GetTemplateCtx(ctx.Input.MetaInput).Get("whoami")
	})

	require.True(t, matched, "could not get correct match value")
	require.True(t, childRan, "matcher subtemplate should run when the matcher matches")
	require.False(t, childWhoamiSet, "an empty extract should not be propagated")
	require.Nil(t, childWhoami, "an empty extract should not be propagated")
}

// TestWorkflowsMatcherSubtemplatesNoMatchDoesNotRunChild keeps the existing
// behaviour: a non matching matcher must not start the subtemplate even when
// the step extracted values.
func TestWorkflowsMatcherSubtemplatesNoMatchDoesNotRunChild(t *testing.T) {
	var childRan bool

	matched := runMatcherExtractWorkflow(t, map[string][]string{"whoami": {"foo"}}, "apache", func(ctx *scan.ScanContext, childOptions *protocols.ExecutorOptions) {
		childRan = true
	})

	require.False(t, matched, "a non matching matcher should not report a match")
	require.False(t, childRan, "a non matching matcher should not start the subtemplate")
}
