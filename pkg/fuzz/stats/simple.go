package stats

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
)

type simpleStats struct {
	totalComponentsTested atomic.Int64
	totalEndpointsTested  atomic.Int64
	totalFuzzedRequests   atomic.Int64
	totalMatchedResults   atomic.Int64
	totalTemplatesTested  atomic.Int64
	totalErroredRequests  atomic.Int64

	statusCodes    sync.Map
	severityCounts sync.Map

	componentsUniqueMap sync.Map
	endpointsUniqueMap  sync.Map
	templatesUniqueMap  sync.Map
	errorGroupedStats   sync.Map
}

func NewSimpleStats() (*simpleStats, error) {
	return &simpleStats{
		totalComponentsTested: atomic.Int64{},
		totalEndpointsTested:  atomic.Int64{},
		totalMatchedResults:   atomic.Int64{},
		totalFuzzedRequests:   atomic.Int64{},
		totalTemplatesTested:  atomic.Int64{},
		totalErroredRequests:  atomic.Int64{},
		statusCodes:           sync.Map{},
		severityCounts:        sync.Map{},
		componentsUniqueMap:   sync.Map{},
		endpointsUniqueMap:    sync.Map{},
		templatesUniqueMap:    sync.Map{},
		errorGroupedStats:     sync.Map{},
	}, nil
}

func (s *simpleStats) Close() {}

func (s *simpleStats) InsertComponent(event ComponentEvent) error {
	componentKey := fmt.Sprintf("%s_%s", event.ComponentName, event.ComponentType)
	if _, ok := s.componentsUniqueMap.Load(componentKey); !ok {
		s.componentsUniqueMap.Store(componentKey, true)
		s.totalComponentsTested.Add(1)
	}

	parsedURL, err := url.Parse(event.URL)
	if err != nil {
		return err
	}

	endpointsKey := fmt.Sprintf("%s_%s", event.siteName, parsedURL.Path)
	if _, ok := s.endpointsUniqueMap.Load(endpointsKey); !ok {
		s.endpointsUniqueMap.Store(endpointsKey, true)
		s.totalEndpointsTested.Add(1)
	}

	return nil
}

func (s *simpleStats) InsertMatchedRecord(event FuzzingEvent) error {
	s.totalFuzzedRequests.Add(1)

	s.incrementStatusCode(event.StatusCode)
	if event.Matched {
		s.totalMatchedResults.Add(1)

		s.incrementSeverityCount(event.Severity)
	}

	if _, ok := s.templatesUniqueMap.Load(event.TemplateID); !ok {
		s.templatesUniqueMap.Store(event.TemplateID, true)
		s.totalTemplatesTested.Add(1)
	}
	return nil
}

func (s *simpleStats) InsertError(event ErrorEvent) error {
	s.totalErroredRequests.Add(1)

	value, _ := s.errorGroupedStats.LoadOrStore(event.Error, &atomic.Int64{})
	if counter, ok := value.(*atomic.Int64); ok {
		counter.Add(1)
	}
	return nil
}

type SimpleStatsResponse struct {
	TotalMatchedResults   int64
	TotalComponentsTested int64
	TotalEndpointsTested  int64
	TotalFuzzedRequests   int64
	TotalTemplatesTested  int64
	TotalErroredRequests  int64
	StatusCodes           map[string]int64
	SeverityCounts        map[string]int64
	ErrorGroupedStats     map[string]int64
}

func (s *simpleStats) GetStatistics() SimpleStatsResponse {
	statusStats := make(map[string]int64)
	s.statusCodes.Range(func(key, value interface{}) bool {
		if count, ok := value.(*atomic.Int64); ok {
			statusStats[formatStatusCode(key.(int))] = count.Load()
		}
		return true
	})

	severityStats := make(map[string]int64)
	s.severityCounts.Range(func(key, value interface{}) bool {
		if count, ok := value.(*atomic.Int64); ok {
			severityStats[key.(string)] = count.Load()
		}
		return true
	})

	errorStats := make(map[string]int64)
	s.errorGroupedStats.Range(func(key, value interface{}) bool {
		if count, ok := value.(*atomic.Int64); ok {
			errorStats[key.(string)] = count.Load()
		}
		return true
	})

	return SimpleStatsResponse{
		TotalMatchedResults:   s.totalMatchedResults.Load(),
		StatusCodes:           statusStats,
		SeverityCounts:        severityStats,
		TotalComponentsTested: s.totalComponentsTested.Load(),
		TotalEndpointsTested:  s.totalEndpointsTested.Load(),
		TotalFuzzedRequests:   s.totalFuzzedRequests.Load(),
		TotalTemplatesTested:  s.totalTemplatesTested.Load(),
		TotalErroredRequests:  s.totalErroredRequests.Load(),
		ErrorGroupedStats:     errorStats,
	}
}

func (s *simpleStats) incrementStatusCode(statusCode int) {
	value, _ := s.statusCodes.LoadOrStore(statusCode, &atomic.Int64{})
	if counter, ok := value.(*atomic.Int64); ok {
		counter.Add(1)
	}
}

func (s *simpleStats) incrementSeverityCount(severity string) {
	value, _ := s.severityCounts.LoadOrStore(severity, &atomic.Int64{})
	if counter, ok := value.(*atomic.Int64); ok {
		counter.Add(1)
	}
}

func formatStatusCode(code int) string {
	escapedText := strings.ToTitle(strings.ReplaceAll(http.StatusText(code), " ", "_"))
	formatted := fmt.Sprintf("%d_%s", code, escapedText)
	return formatted
}
