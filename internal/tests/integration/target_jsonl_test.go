//go:build integration
// +build integration

package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

const (
	targetJSONLAlphaTemplateID = "target-jsonl-alpha"
	targetJSONLBetaTemplateID  = "target-jsonl-beta"
)

type targetJSONLRecord struct {
	URL         string    `json:"url"`
	Tags        []string  `json:"tags,omitempty"`
	ExcludeTags []string  `json:"exclude-tags,omitempty"`
	Templates   *[]string `json:"templates,omitempty"`
}

func TestTargetJSONLTemplateFilters(t *testing.T) {
	templatePaths := writeTargetJSONLTemplates(t)

	scenarios := []struct {
		name     string
		records  func(firstURL, secondURL string) []targetJSONLRecord
		expected func(firstURL, secondURL string) map[string]struct{}
	}{
		{
			name: "clustered templates",
			records: func(firstURL, secondURL string) []targetJSONLRecord {
				return []targetJSONLRecord{
					{URL: firstURL, Tags: []string{targetJSONLAlphaTemplateID, targetJSONLBetaTemplateID}},
					{URL: secondURL, Tags: []string{targetJSONLAlphaTemplateID, targetJSONLBetaTemplateID}},
				}
			},
			expected: func(firstURL, secondURL string) map[string]struct{} {
				return expectedTargetJSONLPairs(
					targetJSONLAlphaTemplateID, firstURL,
					targetJSONLBetaTemplateID, firstURL,
					targetJSONLAlphaTemplateID, secondURL,
					targetJSONLBetaTemplateID, secondURL,
				)
			},
		},
		{
			name: "target exclusions",
			records: func(firstURL, secondURL string) []targetJSONLRecord {
				return []targetJSONLRecord{
					{
						URL:         firstURL,
						Tags:        []string{targetJSONLAlphaTemplateID, targetJSONLBetaTemplateID},
						ExcludeTags: []string{targetJSONLBetaTemplateID},
					},
					{
						URL:         secondURL,
						Tags:        []string{targetJSONLAlphaTemplateID, targetJSONLBetaTemplateID},
						ExcludeTags: []string{targetJSONLAlphaTemplateID},
					},
				}
			},
			expected: func(firstURL, secondURL string) map[string]struct{} {
				return expectedTargetJSONLPairs(
					targetJSONLAlphaTemplateID, firstURL,
					targetJSONLBetaTemplateID, secondURL,
				)
			},
		},
		{
			name: "per-target templates",
			records: func(firstURL, secondURL string) []targetJSONLRecord {
				firstTemplates := []string{templatePaths[0]}
				secondTemplates := []string{templatePaths[1]}
				return []targetJSONLRecord{
					{URL: firstURL, Templates: &firstTemplates},
					{URL: secondURL, Templates: &secondTemplates},
				}
			},
			expected: func(firstURL, secondURL string) map[string]struct{} {
				return expectedTargetJSONLPairs(
					targetJSONLAlphaTemplateID, firstURL,
					targetJSONLBetaTemplateID, secondURL,
				)
			},
		},
	}

	for _, strategy := range []string{"template-spray", "host-spray"} {
		strategy := strategy
		t.Run(strategy, func(t *testing.T) {
			for _, scenario := range scenarios {
				scenario := scenario
				t.Run(scenario.name, func(t *testing.T) {
					var requestCount atomic.Int64
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						requestCount.Add(1)
						_, _ = fmt.Fprint(w, "target-jsonl-integration")
					}))
					t.Cleanup(server.Close)

					firstURL := server.URL + "/first"
					secondURL := server.URL + "/second"
					inputPath := writeTargetJSONLInput(t, scenario.records(firstURL, secondURL))

					results, err := testutils.RunNucleiBareArgsAndGetResults(suite.debug, nil,
						"-list", inputPath,
						"-input-mode", "jsonl",
						"-templates", templatePaths[0],
						"-templates", templatePaths[1],
						"-jsonl",
						"-scan-strategy", strategy,
					)
					if err != nil {
						t.Fatalf("target JSONL scan failed: %v", err)
					}

					assertTargetJSONLResults(t, results, scenario.expected(firstURL, secondURL))
					if got := requestCount.Load(); got != 2 {
						t.Fatalf("unexpected physical request count: got %d, want 2 (one clustered request per target)", got)
					}
				})
			}
		})
	}
}

func writeTargetJSONLTemplates(t *testing.T) [2]string {
	t.Helper()

	templateDir := t.TempDir()
	paths := [2]string{
		filepath.Join(templateDir, targetJSONLAlphaTemplateID+".yaml"),
		filepath.Join(templateDir, targetJSONLBetaTemplateID+".yaml"),
	}
	for index, templateID := range []string{targetJSONLAlphaTemplateID, targetJSONLBetaTemplateID} {
		writeTargetJSONLTemplate(t, paths[index], templateID)
	}
	return paths
}

func writeTargetJSONLTemplate(t *testing.T, path, templateID string) {
	t.Helper()

	template := fmt.Sprintf(`id: %s

info:
  name: Target JSONL integration %s
  author: pdteam
  severity: info
  tags: %s

http:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: word
        words:
          - "target-jsonl-integration"
`, templateID, strings.TrimPrefix(templateID, "target-jsonl-"), templateID)
	if err := os.WriteFile(path, []byte(template), 0600); err != nil {
		t.Fatalf("failed to write integration template %s: %v", templateID, err)
	}
}

func writeTargetJSONLInput(t *testing.T, records []targetJSONLRecord) string {
	t.Helper()

	var data strings.Builder
	encoder := json.NewEncoder(&data)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			t.Fatalf("failed to encode target JSONL record: %v", err)
		}
	}

	inputPath := filepath.Join(t.TempDir(), "targets.jsonl")
	if err := os.WriteFile(inputPath, []byte(data.String()), 0600); err != nil {
		t.Fatalf("failed to write target JSONL input: %v", err)
	}
	return inputPath
}

func expectedTargetJSONLPairs(values ...string) map[string]struct{} {
	pairs := make(map[string]struct{}, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		pairs[targetJSONLPair(values[index], values[index+1])] = struct{}{}
	}
	return pairs
}

func targetJSONLPair(templateID, targetURL string) string {
	return templateID + "|" + targetURL
}

func assertTargetJSONLResults(t *testing.T, results []string, expected map[string]struct{}) {
	t.Helper()

	actual := make(map[string]struct{}, len(results))
	for _, result := range results {
		var event output.ResultEvent
		if err := json.Unmarshal([]byte(result), &event); err != nil {
			t.Fatalf("failed to decode JSONL result %q: %v", result, err)
		}
		pair := targetJSONLPair(event.TemplateID, event.URL)
		if _, duplicate := actual[pair]; duplicate {
			t.Fatalf("duplicate result for %s", pair)
		}
		actual[pair] = struct{}{}
	}

	if len(actual) != len(expected) {
		t.Fatalf("unexpected result count: got %d, want %d\nresults: %v", len(actual), len(expected), actual)
	}
	for pair := range expected {
		if _, ok := actual[pair]; !ok {
			t.Errorf("missing result for %s", pair)
		}
	}
	for pair := range actual {
		if _, ok := expected[pair]; !ok {
			t.Errorf("unexpected result for %s", pair)
		}
	}
}
