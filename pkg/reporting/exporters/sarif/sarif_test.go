package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	upstream "github.com/projectdiscovery/sarif"
	"github.com/stretchr/testify/require"
)

// makeEvent returns a fully populated ResultEvent suitable for the integration tests.
func makeEvent() *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID:   "test-template",
		TemplateURL:  "https://templates.example.com/test-template.yaml",
		Template:     "/tmp/nuclei-templates/cves/test-template.yaml",
		TemplatePath: "/tmp/nuclei-templates/cves/test-template.yaml",
		Type:         "http",
		Host:         "example.com",
		URL:          "https://example.com",
		Path:         "/admin",
		Matched:      "https://example.com/admin",
		IP:           "93.184.216.34",
		MatcherName:  "status-200",
		ExtractorName: "version",
		ExtractedResults: []string{"v1.2.3", "v1.2.4"},
		CURLCommand:   "curl -X GET https://example.com/admin",
		Lines:         []int{0, 42},
		Timestamp:     time.Now(),
		Info: model.Info{
			Name:           "Test Finding",
			Authors:        stringslice.StringSlice{Value: "tester"},
			Description:    "A test vulnerability description.",
			Impact:         "Severe impact",
			Remediation:    "Update to latest version",
			Tags:           stringslice.StringSlice{Value: []string{"test", "rce"}},
			Reference:      stringslice.NewRawStringSlice([]string{"https://ref.example.com/a", "https://ref.example.com/b"}),
			SeverityHolder: severity.Holder{Severity: severity.High},
			Classification: &model.Classification{
				CWEID:     stringslice.StringSlice{Value: []string{"CWE-79"}},
				CVSSScore: 8.7,
			},
		},
	}
}

// helper-level unit tests

func TestNormalizeValue(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"   \t\n  ", ""},
		{"  hello  world  ", "hello world"},
		{"line1\nline2\tline3", "line1 line2 line3"},
		{"single", "single"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, normalizeValue(tt.in), "input=%q", tt.in)
	}
}

func TestNormalizeAndTruncate(t *testing.T) {
	require.Equal(t, "", normalizeAndTruncate("", 100))
	require.Equal(t, "hello", normalizeAndTruncate(" hello ", 100))
	require.Equal(t, "hello", normalizeAndTruncate("hello", 0))

	long := strings.Repeat("x", 500)
	got := normalizeAndTruncate(long, 100)
	require.Len(t, got, 100)
	require.True(t, strings.HasSuffix(got, "..."))
	require.Equal(t, strings.Repeat("x", 97)+"...", got)
}

func TestNormalizePath(t *testing.T) {
	require.Equal(t, "", normalizePath(""))
	require.Equal(t, "", normalizePath("   "))
	require.Equal(t, "a/b/c.yaml", normalizePath("a\\b\\c.yaml"))
	require.Equal(t, "/a/b", normalizePath("/a/./b"))
	require.Equal(t, "a/b", normalizePath("a/b/"))
}

func TestAppendIfMissing(t *testing.T) {
	out := appendIfMissing([]string{"a", "b"}, "a")
	require.Equal(t, []string{"a", "b"}, out)
	out = appendIfMissing([]string{"a", "b"}, "c")
	require.Equal(t, []string{"a", "b", "c"}, out)
}

func TestBuildCWETag(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{"abc", ""},
		{"CWE-79", "external/cwe/cwe-79"},
		{"cwe-22", "external/cwe/cwe-22"},
		{"79", "external/cwe/cwe-79"},
		{"  CWE-89  ", "external/cwe/cwe-89"},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, buildCWETag(tt.in), "input=%q", tt.in)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	require.Equal(t, "", firstNonEmpty())
	require.Equal(t, "", firstNonEmpty("", "  "))
	require.Equal(t, "first", firstNonEmpty("first", "second"))
	require.Equal(t, "second", firstNonEmpty("", "second", "third"))
}

func TestFirstPositiveLine(t *testing.T) {
	require.Equal(t, 0, firstPositiveLine(nil))
	require.Equal(t, 0, firstPositiveLine([]int{}))
	require.Equal(t, 0, firstPositiveLine([]int{0, -1, 0}))
	require.Equal(t, 5, firstPositiveLine([]int{0, 0, 5, 7}))
	require.Equal(t, 7, firstPositiveLine([]int{7}))
}

func TestFormatExtractedResults(t *testing.T) {
	require.Equal(t, "", formatExtractedResults(nil))
	require.Equal(t, "", formatExtractedResults([]string{}))
	require.Equal(t, "", formatExtractedResults([]string{"", "  "}))

	require.Equal(t, "a, b", formatExtractedResults([]string{"a", "b"}))

	values := []string{"a", "b", "c", "d", "e", "f", "g"}
	got := formatExtractedResults(values)
	require.Contains(t, got, "a, b, c, d, e")
	require.Contains(t, got, "and 2 more")
}

func TestGetResultTarget(t *testing.T) {
	require.Equal(t, "https://example.com/match", getResultTarget(&output.ResultEvent{
		Matched: "https://example.com/match",
		URL:     "https://example.com",
	}))
	require.Equal(t, "https://example.com", getResultTarget(&output.ResultEvent{
		URL:  "https://example.com",
		Host: "example.com",
	}))
	require.Equal(t, "example.com", getResultTarget(&output.ResultEvent{Host: "example.com"}))
	require.Equal(t, "/path", getResultTarget(&output.ResultEvent{Path: "/path"}))
	require.Equal(t, "unknown target", getResultTarget(&output.ResultEvent{}))
}

func TestBuildArtifactURI(t *testing.T) {
	require.Equal(t,
		"cves/test.yaml",
		buildArtifactURI(&output.ResultEvent{Template: "/home/user/nuclei-templates/cves/test.yaml"}),
	)
	require.Equal(t,
		"cves/test.yaml",
		buildArtifactURI(&output.ResultEvent{Template: "C:\\src\\nuclei-templates\\cves\\test.yaml"}),
	)
	require.Equal(t,
		"local/template.yaml",
		buildArtifactURI(&output.ResultEvent{Template: "/local/template.yaml"}),
	)
	require.Equal(t,
		"some/file",
		buildArtifactURI(&output.ResultEvent{Path: "/some/file"}),
	)
	require.Equal(t,
		"nuclei-results/my-id.txt",
		buildArtifactURI(&output.ResultEvent{TemplateID: "my-id"}),
	)
	require.Equal(t,
		"nuclei-results/result.txt",
		buildArtifactURI(&output.ResultEvent{}),
	)
}

func TestBuildRuleTags(t *testing.T) {
	event := &output.ResultEvent{
		Info: model.Info{
			Tags: stringslice.StringSlice{Value: []string{"rce", "rce", "  "}},
			Classification: &model.Classification{
				CWEID: stringslice.StringSlice{Value: []string{"CWE-79"}},
			},
		},
	}
	tags := buildRuleTags(event)
	require.Equal(t, []string{"security", "rce", "external/cwe/cwe-79"}, tags)
}

func TestGetReferences(t *testing.T) {
	require.Nil(t, getReferences(&output.ResultEvent{}))

	refs := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		refs = append(refs, "https://example.com/r")
	}
	event := &output.ResultEvent{
		Info: model.Info{Reference: stringslice.NewRawStringSlice(refs)},
	}
	got := getReferences(event)
	require.Len(t, got, maxRuleReferences)
}

func TestAddDetail(t *testing.T) {
	var lines []string
	addDetail(&lines, "Label", "")
	require.Empty(t, lines)
	addDetail(&lines, "Label", "value")
	require.Equal(t, []string{"Label: value"}, lines)
}

func TestBuildLocationRegion(t *testing.T) {
	loc := buildLocation(&output.ResultEvent{Lines: []int{0, 42}}, "target")
	require.NotNil(t, loc.PhysicalLocation.Region)
	require.Equal(t, 42, loc.PhysicalLocation.Region.StartLine)

	loc = buildLocation(&output.ResultEvent{Lines: []int{0, 0}}, "target")
	require.Nil(t, loc.PhysicalLocation.Region)
}

func TestBuildRuleDescription(t *testing.T) {
	got := buildRuleDescription(&output.ResultEvent{
		TemplateURL: "https://example.com/t.yaml",
		Info:        model.Info{Description: "desc"},
	}, "fallback")
	require.Equal(t, "desc\nMore details at\nhttps://example.com/t.yaml", got)

	got = buildRuleDescription(&output.ResultEvent{}, "fallback name")
	require.Equal(t, "fallback name", got)
}

func TestBuildRuleHelpText(t *testing.T) {
	got := buildRuleHelpText(&output.ResultEvent{})
	require.Equal(t, "No additional template metadata was provided by the scanner.", got)

	event := makeEvent()
	got = buildRuleHelpText(event)
	require.Contains(t, got, "Impact: Severe impact")
	require.Contains(t, got, "Remediation: Update to latest version")
	require.Contains(t, got, "References:")
	require.Contains(t, got, "More details:")
}

func TestBuildRuleHelpMarkdown(t *testing.T) {
	got := buildRuleHelpMarkdown(makeEvent(), "Test Finding")
	require.Contains(t, got, "### Test Finding")
	require.Contains(t, got, "- **Impact:** Severe impact")
	require.Contains(t, got, "- **Remediation:** Update to latest version")
	require.Contains(t, got, "**References**")
}

func TestBuildResultMessage(t *testing.T) {
	msg := buildResultMessage(makeEvent(), "header", "test-template")
	require.NotNil(t, msg)
	require.Contains(t, msg.Text, "header")
	require.Contains(t, msg.Text, "Target: https://example.com/admin")
	require.Contains(t, msg.Text, "IP: 93.184.216.34")
	require.Contains(t, msg.Text, "Matcher: status-200")
	require.Contains(t, msg.Text, "Extractor: version")
	require.Contains(t, msg.Text, "Reproduce:")
	require.Contains(t, msg.Text, "```bash")
	require.Contains(t, msg.Markdown, "**Triage Details**")
	require.Contains(t, msg.Markdown, "- **Target:** https://example.com/admin")
}

func TestBuildResultProperties(t *testing.T) {
	props := buildResultProperties(makeEvent(), "https://example.com/admin")
	require.NotNil(t, props)
	require.Equal(t, "https://example.com/admin", props["target"])
	require.Equal(t, "status-200", props["matcher"])
	require.Equal(t, "version", props["extractor"])
	require.Contains(t, props["template-path"], "test-template.yaml")

	extracted, ok := props["extracted-results"].([]string)
	require.True(t, ok)
	require.Equal(t, []string{"v1.2.3", "v1.2.4"}, extracted)

	require.Nil(t, buildResultProperties(&output.ResultEvent{}, ""))
}

// severity table
func TestGetSeverity(t *testing.T) {
	exp, err := New(&Options{File: "x.sarif"})
	require.NoError(t, err)

	cases := []struct {
		sev   string
		level upstream.Level
		score string
	}{
		{"critical", upstream.Error, "9.4"},
		{"high", upstream.Error, "8"},
		{"medium", upstream.Note, "5"},
		{"low", upstream.Note, "2"},
		{"info", upstream.None, "1"},
	}
	for _, c := range cases {
		gotLevel, gotScore := exp.getSeverity(c.sev)
		require.Equal(t, c.level, gotLevel, "sev=%s", c.sev)
		require.Equal(t, c.score, gotScore, "sev=%s", c.sev)
	}
}

// integration: Export + Close round-trip

func TestNew_InitializesEmpty(t *testing.T) {
	exp, err := New(&Options{File: "x.sarif"})
	require.NoError(t, err)
	require.NotNil(t, exp.sarif)
	require.NotNil(t, exp.mutex)
	require.Empty(t, exp.rules)
	require.Empty(t, exp.rulemap)
}

func TestClose_NoEventsWritesNoFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)
	require.NoError(t, exp.Close())
	_, statErr := os.Stat(out)
	require.True(t, os.IsNotExist(statErr))
}

func TestExport_Close_RoundTrip(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)

	require.NoError(t, exp.Export(makeEvent()))
	require.NoError(t, exp.Close())

	bin, err := os.ReadFile(out)
	require.NoError(t, err)
	require.NotEmpty(t, bin)

	var log upstream.SarifLog
	require.NoError(t, json.Unmarshal(bin, &log), "output is not valid JSON / SarifLog")
	require.Equal(t, "2.1.0", log.Version)
	require.NotEmpty(t, log.Schema)
	require.Len(t, log.Runs, 1)

	run := log.Runs[0]
	require.Equal(t, "Nuclei", run.Tool.Driver.Name)
	require.Equal(t, "ProjectDiscovery", run.Tool.Driver.Organization)
	require.NotEmpty(t, run.Tool.Driver.DownloadUri)
	require.NotEmpty(t, run.Tool.Driver.InformationUri)
	require.Len(t, run.Tool.Driver.Rules, 1)

	rule := run.Tool.Driver.Rules[0]
	require.Equal(t, "test-template", rule.Id)
	require.Equal(t, "Test Finding", rule.Name)
	require.Equal(t, "https://templates.example.com/test-template.yaml", rule.HelpUri)
	require.NotNil(t, rule.ShortDescription)
	require.NotNil(t, rule.FullDescription)
	require.NotNil(t, rule.Help)

	require.Len(t, run.Result, 1)
	res := run.Result[0]
	require.Equal(t, "test-template", res.RuleId)
	require.Equal(t, 0, res.RuleIndex)
	require.Equal(t, upstream.Error, res.Level)
	require.NotNil(t, res.Message)
	require.Contains(t, res.Message.Text, "Test Finding")
	require.Contains(t, res.Message.Text, "test-template")
	require.Len(t, res.Locations, 1)

	require.Len(t, run.Invocations, 1)
	require.True(t, run.Invocations[0].ExecutionSuccessful)
}

func TestExport_FallbackRuleID(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)

	event := makeEvent()
	event.TemplateID = ""
	event.Info.Name = ""
	require.NoError(t, exp.Export(event))
	require.NoError(t, exp.Close())

	require.Len(t, exp.rules, 1)
	require.Equal(t, fallbackTemplateRuleID, exp.rules[0].Id)
	require.Equal(t, fallbackTemplateRuleID, exp.rules[0].Name)
}

func TestExport_StableRuleIndices(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)

	a := makeEvent()
	a.TemplateID = "rule-a"
	b := makeEvent()
	b.TemplateID = "rule-b"

	require.NoError(t, exp.Export(a))
	require.NoError(t, exp.Export(b))
	require.NoError(t, exp.Export(a))
	require.NoError(t, exp.Export(b))

	require.Len(t, exp.rules, 2)
	require.Equal(t, "rule-a", exp.rules[0].Id)
	require.Equal(t, "rule-b", exp.rules[1].Id)
	require.Equal(t, 0, exp.rulemap["rule-a"])
	require.Equal(t, 1, exp.rulemap["rule-b"])

	require.NoError(t, exp.Close())

	bin, err := os.ReadFile(out)
	require.NoError(t, err)
	var log upstream.SarifLog
	require.NoError(t, json.Unmarshal(bin, &log))
	require.Len(t, log.Runs, 1)
	require.Len(t, log.Runs[0].Result, 4)

	for i, want := range []string{"rule-a", "rule-b", "rule-a", "rule-b"} {
		res := log.Runs[0].Result[i]
		require.Equal(t, want, res.RuleId, "result %d ruleId", i)
		require.Equal(t, log.Runs[0].Tool.Driver.Rules[res.RuleIndex].Id, res.RuleId,
			"result %d index points to wrong rule", i)
	}
}

func TestExport_CVSSScoreOverridesSeverity(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)

	event := makeEvent()
	event.Info.SeverityHolder.Severity = severity.Medium
	event.Info.Classification.CVSSScore = 7.3
	require.NoError(t, exp.Export(event))

	require.Len(t, exp.rules, 1)
	props, ok := exp.rules[0].Properties.(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "7.3", props["security-severity"])
}

func TestExport_Concurrency(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	exp, err := New(&Options{File: out})
	require.NoError(t, err)

	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			errs <- exp.Export(makeEvent())
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}

	require.Len(t, exp.rules, 1)
	require.NoError(t, exp.Close())

	bin, err := os.ReadFile(out)
	require.NoError(t, err)
	var log upstream.SarifLog
	require.NoError(t, json.Unmarshal(bin, &log))
	require.Len(t, log.Runs[0].Result, workers)
}
