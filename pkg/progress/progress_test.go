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
		tasks       uint64
		totalTasks  uint64
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
		{
			name:        "tasks are counted",
			requests:    50,
			total:       200,
			tasks:       3,
			totalTasks:  4,
			wantPercent: "75",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			stats := &statsClientSpy{
				counters: map[string]uint64{
					"requests":   test.requests,
					"total":      test.total,
					"tasks":      test.tasks,
					"totalTasks": test.totalTasks,
				},
				statics: map[string]interface{}{"startedAt": time.Now().Add(-time.Second)},
			}

			// When
			results := metricsMap(stats)

			// Then
			require.Equal(t, test.wantPercent, results["percent"])
			require.Equal(t, clistats.String(test.tasks), results["tasks"])
			require.Equal(t, clistats.String(test.totalTasks), results["totalTasks"])
		})
	}
}

func TestPrintCallbackTasks(t *testing.T) {
	tests := []struct {
		name       string
		tasks      uint64
		totalTasks uint64
		want       string
	}{
		{
			name: "tasks are not counted",
			want: "| Requests: 10/40 (25%)",
		},
		{
			name:       "tasks are counted",
			tasks:      1,
			totalTasks: 2,
			want:       "| Requests: 10/40 | Tasks: 1/2 (50%)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ticker := &StatsTicker{}
			stats := &statsClientSpy{
				counters: map[string]uint64{
					"requests":   10,
					"total":      40,
					"tasks":      test.tasks,
					"totalTasks": test.totalTasks,
				},
				statics: map[string]interface{}{"startedAt": time.Now()},
			}

			out, ok := ticker.makePrintCallback()(stats).(string)
			require.True(t, ok)
			require.Contains(t, out, test.want)
		})
	}
}

func TestPrintCallbackZeroTotal(t *testing.T) {
	ticker := &StatsTicker{}
	stats := &statsClientSpy{
		counters: map[string]uint64{"requests": 0, "total": 0},
		statics:  map[string]interface{}{"startedAt": time.Now()},
	}

	out, ok := ticker.makePrintCallback()(stats).(string)
	require.True(t, ok)
	require.Contains(t, out, "(0%)")
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

func (s *statsClientSpy) AddCounter(key string, value uint64) {
	if s.counters == nil {
		s.counters = map[string]uint64{}
	}
	s.counters[key] = value
}

func (s *statsClientSpy) GetCounter(key string) (uint64, bool) {
	value, ok := s.counters[key]
	return value, ok
}

func (s *statsClientSpy) IncrementCounter(key string, count int) {
	if s.counters == nil {
		s.counters = map[string]uint64{}
	}
	s.counters[key] += uint64(count)
}

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

func TestInitProbeStartsTickerOnce(t *testing.T) {
	// Given
	stats := &statsClientSpy{}
	ticker := &StatsTicker{
		active:       true,
		stats:        stats,
		tickDuration: time.Second,
	}

	// When
	ticker.InitProbe(60, 1, 60)
	ticker.IncrementProbes()
	ticker.IncrementProbes()
	ticker.Init(60, 1, 120)

	// Then
	require.True(t, stats.started)
	require.True(t, stats.periodicStatsRequested)

	// the probe fields are registered and incremented
	probed, ok := stats.GetCounter("probed")
	require.True(t, ok)
	require.Equal(t, uint64(2), probed)
	probeTotal, ok := stats.GetCounter("probeTotal")
	require.True(t, ok)
	require.Equal(t, uint64(60), probeTotal)

	// Init after InitProbe only updates the estimated request total and
	// does not re-register or reset the probe counters
	total, ok := stats.GetCounter("total")
	require.True(t, ok)
	require.Equal(t, uint64(120), total)
	probed, _ = stats.GetCounter("probed")
	require.Equal(t, uint64(2), probed)
}

func TestInitWithoutProbeBehavesAsBefore(t *testing.T) {
	// Given
	stats := &statsClientSpy{}
	ticker := &StatsTicker{
		active:       true,
		stats:        stats,
		tickDuration: time.Second,
	}

	// When
	ticker.Init(60, 1, 120)

	// Then
	require.True(t, stats.started)
	total, ok := stats.GetCounter("total")
	require.True(t, ok)
	require.Equal(t, uint64(120), total)
	_, ok = stats.GetCounter("probed")
	require.False(t, ok)
}

func TestPrintCallbackProbing(t *testing.T) {
	tests := []struct {
		name       string
		probed     uint64
		probeTotal uint64
		want       string
		notWant    string
	}{
		{
			name:       "probing in progress",
			probed:     3,
			probeTotal: 10,
			want:       "| Probing: 3/10 (30%)",
			notWant:    "| Requests:",
		},
		{
			name:       "probing finished",
			probed:     10,
			probeTotal: 10,
			want:       "| Requests: 10/40 (25%)",
			notWant:    "| Probing:",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ticker := &StatsTicker{}
			stats := &statsClientSpy{
				counters: map[string]uint64{
					"requests":   10,
					"total":      40,
					"probed":     test.probed,
					"probeTotal": test.probeTotal,
				},
				statics: map[string]interface{}{"startedAt": time.Now()},
			}

			out, ok := ticker.makePrintCallback()(stats).(string)
			require.True(t, ok)
			require.Contains(t, out, test.want)
			require.NotContains(t, out, test.notWant)
		})
	}
}
