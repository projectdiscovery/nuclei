package reporting

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/jsonexporter"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/jsonl"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/trackers/filters"
	"github.com/stretchr/testify/require"
)

func TestReportingDedupeRedirectedInputs(t *testing.T) {
	for _, concurrent := range []bool{false, true} {
		name := "sequential"
		if concurrent {
			name = "concurrent"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			jsonPath := filepath.Join(dir, "report.json")
			jsonlPath := filepath.Join(dir, "report.jsonl")
			sarifPath := filepath.Join(dir, "report.sarif")
			markdownPath := filepath.Join(dir, "markdown")
			client, err := New(&Options{
				JSONExporter:     &jsonexporter.Options{File: jsonPath},
				JSONLExporter:    &jsonl.Options{File: jsonlPath},
				SarifExporter:    &sarif.Options{File: sarifPath},
				MarkdownExporter: &markdown.Options{Directory: markdownPath},
			}, "", false)
			require.NoError(t, err)
			tracker := &recordingTracker{}
			client.RegisterTracker(tracker)
			events := []output.ResultEvent{
				{TemplateID: "gitlab-detect", Type: "http", Host: "example.com", Port: "80", Scheme: "http", URL: "http://example.com:80", Matched: "https://example.com:443/users/sign_in"},
				{TemplateID: "gitlab-detect", Type: "http", Host: "example.com", Port: "443", Scheme: "https", URL: "https://example.com:443", Matched: "https://example.com:443/users/sign_in"},
			}
			var wg sync.WaitGroup
			start := make(chan struct{})
			for range 16 {
				for _, event := range events {
					event.Info.SeverityHolder.Severity = severity.Info
					if concurrent {
						wg.Add(1)
						go func() {
							defer wg.Done()
							<-start
							if err := client.CreateIssue(&event); err != nil {
								t.Errorf("report finding: %v", err)
							}
						}()
					} else if err := client.CreateIssue(&event); err != nil {
						t.Errorf("report finding: %v", err)
					}
				}
			}
			close(start)
			wg.Wait()
			client.Close()

			wantURLs := []string{events[0].URL, events[1].URL}
			require.ElementsMatch(t, wantURLs, tracker.urls)
			data, err := os.ReadFile(jsonPath)
			require.NoError(t, err)
			var rows []output.ResultEvent
			require.NoError(t, json.Unmarshal(data, &rows))
			var urls []string
			for _, row := range rows {
				urls = append(urls, row.URL)
			}
			require.ElementsMatch(t, wantURLs, urls)

			data, err = os.ReadFile(jsonlPath)
			require.NoError(t, err)
			urls = nil
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				var row output.ResultEvent
				require.NoError(t, json.Unmarshal(scanner.Bytes(), &row))
				urls = append(urls, row.URL)
			}
			require.NoError(t, scanner.Err())
			require.ElementsMatch(t, wantURLs, urls)

			data, err = os.ReadFile(sarifPath)
			require.NoError(t, err)
			var report struct {
				Runs []struct{ Results []json.RawMessage }
			}
			require.NoError(t, json.Unmarshal(data, &report))
			require.Len(t, report.Runs, 1)
			require.Len(t, report.Runs[0].Results, 2)

			files, err := filepath.Glob(filepath.Join(markdownPath, "*.md"))
			require.NoError(t, err)
			require.Len(t, files, 3, "two finding reports and the index must be written")
		})
	}
}

type recordingTracker struct {
	mu   sync.Mutex
	urls []string
}

func (t *recordingTracker) Name() string                          { return "recording" }
func (t *recordingTracker) ShouldFilter(*output.ResultEvent) bool { return true }
func (t *recordingTracker) CloseIssue(*output.ResultEvent) error  { return nil }
func (t *recordingTracker) CreateIssue(event *output.ResultEvent) (*filters.CreateIssueResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.urls = append(t.urls, event.URL)
	return &filters.CreateIssueResponse{IssueID: "test"}, nil
}
