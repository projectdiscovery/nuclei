package runner

import (
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestEstimateSecondsTakesTheSlowestBound(t *testing.T) {
	r := &Runner{options: &types.Options{
		RateLimit: 150, RateLimitDuration: time.Second,
		TemplateThreads: 25, BulkSize: 25,
		HeadlessTemplateThreads: 10, HeadlessBulkSize: 10,
	}}

	require.Equal(t, 20, r.estimateSeconds(3000, 3000, 0, 12), "rate limit bound")
	require.Equal(t, 10, r.estimateSeconds(52, 41, 660, 660), "one long entry runs its requests in sequence")
	require.Equal(t, 9, r.estimateSeconds(100, 0, 60000, 60), "headless cost spreads over the headless pool")

	r.options.RateLimit = 0
	require.Equal(t, 0, r.estimateSeconds(3000, 3000, 0, 1), "no rate limit, cost spread over 625 slots")
}
