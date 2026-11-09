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
	template *templates.Template
	request  protocols.Request
}

// Replay runs the matchers and extractors of templatesList over every event
// in the corpus at path and returns the findings sorted, so two replays diff
// line by line. An event replays on the template and request that produced
// it, and a single-request event also on every template sending the same
// request.
func Replay(path string, templatesList []*templates.Template) ([]*output.ResultEvent, error) {
	byRequest := make(map[string][]target)
	byCluster := make(map[string][]target)
	for _, template := range templatesList {
		requests := templateRequests(template)
		for i, request := range requests {
			byRequest[template.ID+"\x00"+strconv.Itoa(i)] = []target{{template: template, request: request}}
		}
		if keyed, ok := singleKeyed(requests); ok {
			key := strconv.FormatUint(keyed.TmplClusterKey(), 10)
			byCluster[key] = append(byCluster[key], target{template: template, request: requests[0]})
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
	slices.SortStableFunc(results, compareResults)
	return results, nil
}

func singleKeyed(requests []protocols.Request) (clusterKeyed, bool) {
	if len(requests) != 1 {
		return nil, false
	}
	keyed, ok := requests[0].(clusterKeyed)
	return keyed, ok
}

func replayEvent(target target, event output.InternalEvent) []*output.ResultEvent {
	// operators add their values to the event, and a cluster event carries
	// the first member's identity
	event = maps.Clone(event)
	event["template-id"] = target.template.ID
	event["template-path"] = target.template.Path
	event["template-info"] = target.template.Info
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
