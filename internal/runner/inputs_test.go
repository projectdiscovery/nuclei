package runner

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFormatHTTPProbeProgress(t *testing.T) {
	tests := []struct {
		name      string
		processed int64
		total     int64
		elapsed   time.Duration
		want      string
	}{
		{
			name:      "in progress with eta",
			processed: 25,
			total:     100,
			elapsed:   5 * time.Second,
			want:      "[httpx] | Hosts: 25/100 (25%) | RPS: 5 | ETA: 15s",
		},
		{
			name:      "completed",
			processed: 100,
			total:     100,
			elapsed:   10 * time.Second,
			want:      "[httpx] | Hosts: 100/100 (100%) | RPS: 10 | ETA: 0s",
		},
		{
			name:      "processed is capped at total",
			processed: 101,
			total:     100,
			elapsed:   10 * time.Second,
			want:      "[httpx] | Hosts: 100/100 (100%) | RPS: 10 | ETA: 0s",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, formatHTTPProbeProgress(test.processed, test.total, test.elapsed))
		})
	}
}
