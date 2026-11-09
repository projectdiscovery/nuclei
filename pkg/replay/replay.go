package replay

import (
	"bufio"
	"bytes"
	"cmp"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

type target struct {
	source  source
	request protocols.Request
}

// Replay runs the matchers and extractors of templatesList over every event
// in the corpus at path and returns the findings sorted, so two replays diff
// line by line. An event replays on the template and request that produced
// it, and a single-request event also on every template sending the same
// request.
func Replay(path string, templatesList []*templates.Template) ([]*output.ResultEvent, error) {
	byRequest := make(map[string][]target)
	byCluster := make(map[string][]target)
	for _, source := range sources(templatesList) {
		for i, request := range source.requests {
			byRequest[source.id+"\x00"+strconv.Itoa(i)] = []target{{source: source, request: request}}
		}
		if len(source.requests) == 1 && source.clustered {
			if key, ok := clusterKey(source.requests[0]); ok {
				byCluster[key] = append(byCluster[key], target{source: source, request: source.requests[0]})
			}
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	var results []*output.ResultEvent
	reader := bufio.NewReader(file)
	for number := 1; ; number++ {
		line, readErr := reader.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var stored record[map[string]json.Message]
			if err := json.Unmarshal(line, &stored); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, number, err)
			}
			event, err := decodeEvent(stored.Event)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", path, number, err)
			}
			targets := byRequest[stored.TemplateID+"\x00"+strconv.Itoa(stored.Request)]
			if stored.ClusterKey != "" {
				targets = byCluster[stored.ClusterKey]
			}
			for _, target := range targets {
				results = append(results, replayEvent(target, event)...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	// extractors keep values in a map, so their order changes between runs
	for _, result := range results {
		slices.Sort(result.ExtractedResults)
	}
	slices.SortStableFunc(results, compareResults)
	return results, nil
}

func replayEvent(target target, event output.InternalEvent) []*output.ResultEvent {
	// operators add their values to the event, and a cluster event carries
	// the first member's identity
	event = maps.Clone(event)
	event["template-id"] = target.source.id
	event["template-path"] = target.source.path
	event["template-info"] = target.source.info
	return eventcreator.CreateEvent(target.request, event, false).Results
}

func compareResults(a, b *output.ResultEvent) int {
	return cmp.Or(
		strings.Compare(a.TemplateID, b.TemplateID),
		strings.Compare(a.Host, b.Host),
		strings.Compare(a.Matched, b.Matched),
		strings.Compare(a.MatcherName, b.MatcherName),
		strings.Compare(a.ExtractorName, b.ExtractorName),
		strings.Compare(strings.Join(a.ExtractedResults, "\x00"), strings.Join(b.ExtractedResults, "\x00")),
	)
}
