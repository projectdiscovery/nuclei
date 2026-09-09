package progress

import (
	"testing"
	"time"

	"github.com/projectdiscovery/clistats"
	"github.com/stretchr/testify/require"
)

func TestStatsTickerInit_registersPeriodicStatsOnly_whenIntervalIsPositive(t *testing.T) {
	tests := []struct {
		name              string
		tickDuration      time.Duration
		wantPeriodicStats bool
	}{
		{
			name:              "interval is disabled",
			tickDuration:      -1,
			wantPeriodicStats: false,
		},
		{
			name:              "interval is positive",
			tickDuration:      time.Second,
			wantPeriodicStats: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			stats := &statsClientSpy{}
			ticker := &StatsTicker{
				active:       true,
				stats:        stats,
				tickDuration: test.tickDuration,
			}

			// When
			ticker.Init(1, 1, 1)

			// Then
			require.True(t, stats.started)
			require.Equal(t, test.wantPeriodicStats, stats.periodicStatsRequested)
		})
	}
}

func TestMetricsMapPercent(t *testing.T) {
	tests := []struct {
		name        string
		requests    uint64
		total       uint64
		wantPercent string
	}{
		{
			name:        "total is known",
			requests:    50,
			total:       200,
			wantPercent: "25",
		},
		{
			name:        "total is unknown",
			requests:    80,
			total:       0,
			wantPercent: "0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			stats := &statsClientSpy{
				counters: map[string]uint64{"requests": test.requests, "total": test.total},
				statics:  map[string]interface{}{"startedAt": time.Now().Add(-time.Second)},
			}

			// When
			results := metricsMap(stats)

			// Then
			require.Equal(t, test.wantPercent, results["percent"])
		})
	}
}

type statsClientSpy struct {
	periodicStatsRequested bool
	started                bool
	counters               map[string]uint64
	statics                map[string]interface{}
}

func (s *statsClientSpy) Start() error {
	s.started = true
	return nil
}

func (s *statsClientSpy) Stop() error {
	return nil
}

func (s *statsClientSpy) AddCounter(string, uint64) {}

func (s *statsClientSpy) GetCounter(key string) (uint64, bool) {
	value, ok := s.counters[key]
	return value, ok
}

func (s *statsClientSpy) IncrementCounter(string, int) {}

func (s *statsClientSpy) AddStatic(string, interface{}) {}

func (s *statsClientSpy) GetStatic(key string) (interface{}, bool) {
	value, ok := s.statics[key]
	return value, ok
}

func (s *statsClientSpy) AddDynamic(string, clistats.DynamicCallback) {}

func (s *statsClientSpy) GetDynamic(string) (clistats.DynamicCallback, bool) {
	return nil, false
}

func (s *statsClientSpy) GetStatResponse(time.Duration, func(string, error) error) {
	s.periodicStatsRequested = true
}
