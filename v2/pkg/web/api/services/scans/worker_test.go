package scans

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/stretchr/testify/require"
)

func TestGetScanPercentage(t *testing.T) {
	progress, _ := progress.NewStatsTicker(0, false, false, false, 0)
	progress.Init(10, 1, 10)

	percentFunc := makePercentReturnFunc(progress)

	progress.IncrementRequests()
	require.Equal(t, float64(10.0), percentFunc(), "could not get correct percentage")
}
