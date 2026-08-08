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

type statsClientSpy struct {
	periodicStatsRequested bool
	started                bool
}

func (s *statsClientSpy) Start() error {
	s.started = true
	return nil
}

func (s *statsClientSpy) Stop() error {
	return nil
}

func (s *statsClientSpy) AddCounter(string, uint64) {}

func (s *statsClientSpy) GetCounter(string) (uint64, bool) {
	return 0, false
}

func (s *statsClientSpy) IncrementCounter(string, int) {}

func (s *statsClientSpy) AddStatic(string, interface{}) {}

func (s *statsClientSpy) GetStatic(string) (interface{}, bool) {
	return nil, false
}

func (s *statsClientSpy) AddDynamic(string, clistats.DynamicCallback) {}

func (s *statsClientSpy) GetDynamic(string) (clistats.DynamicCallback, bool) {
	return nil, false
}

func (s *statsClientSpy) GetStatResponse(time.Duration, func(string, error) error) {
	s.periodicStatsRequested = true
}
