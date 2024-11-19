// Tests ported from ZAP Java version of the algorithm

package time

import (
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	correlationErrorRange = float64(0.1)
	slopeErrorRange       = float64(0.2)
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func Test_should_generate_alternating_sequences(t *testing.T) {
	var generatedDelays []float64
	reqSender := func(delay int) (float64, error) {
		generatedDelays = append(generatedDelays, float64(delay))
		return float64(delay), nil
	}
	matched, _, err := checkTimingDependency(4, 15, correlationErrorRange, slopeErrorRange, reqSender)
	require.NoError(t, err)
	require.True(t, matched)
	require.EqualValues(t, []float64{15, 1, 15, 1}, generatedDelays)
}

func Test_should_giveup_non_injectable(t *testing.T) {
	var timesCalled int
	reqSender := func(delay int) (float64, error) {
		timesCalled++
		return 0.5, nil
	}
	matched, _, err := checkTimingDependency(4, 15, correlationErrorRange, slopeErrorRange, reqSender)
	require.NoError(t, err)
	require.False(t, matched)
	require.Equal(t, 1, timesCalled)
}

func Test_should_giveup_slow_non_injectable(t *testing.T) {
	var timesCalled int
	reqSender := func(delay int) (float64, error) {
		timesCalled++
		return 10 + rng.Float64()*0.5, nil
	}
	matched, _, err := checkTimingDependency(4, 15, correlationErrorRange, slopeErrorRange, reqSender)
	require.NoError(t, err)
	require.False(t, matched)
	require.LessOrEqual(t, timesCalled, 3)
}

func Test_should_giveup_slow_non_injectable_realworld(t *testing.T) {
	var timesCalled int
	var iteration = 0
	counts := []float64{21, 11, 21, 11}
	reqSender := func(delay int) (float64, error) {
		timesCalled++
		iteration++
		return counts[iteration-1], nil
	}
	matched, _, err := checkTimingDependency(4, 15, correlationErrorRange, slopeErrorRange, reqSender)
	require.NoError(t, err)
	require.False(t, matched)
	require.LessOrEqual(t, timesCalled, 4)
}

func Test_should_detect_dependence_with_small_error(t *testing.T) {
	reqSender := func(delay int) (float64, error) {
		return float64(delay) + rng.Float64()*0.5, nil
	}
	matched, reason, err := checkTimingDependency(4, 15, correlationErrorRange, slopeErrorRange, reqSender)
	require.NoError(t, err)
	require.True(t, matched)
	require.NotEmpty(t, reason)
}

func Test_LinearRegression_Numerical_stability(t *testing.T) {
	variables := [][]float64{
		{1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {1, 1}, {2, 2}, {2, 2}, {2, 2},
	}
	slope := float64(1)
	correlation := float64(1)

	regression := newSimpleLinearRegression()
	for _, v := range variables {
		regression.AddPoint(v[0], v[1])
	}
	require.True(t, almostEqual(regression.slope, slope))
	require.True(t, almostEqual(regression.correlation, correlation))
}

func Test_LinearRegression_exact_verify(t *testing.T) {
	variables := [][]float64{
		{1, 1}, {2, 3},
	}
	slope := float64(2)
	correlation := float64(1)

	regression := newSimpleLinearRegression()
	for _, v := range variables {
		regression.AddPoint(v[0], v[1])
	}
	require.True(t, almostEqual(regression.slope, slope))
	require.True(t, almostEqual(regression.correlation, correlation))
}

func Test_LinearRegression_known_verify(t *testing.T) {
	variables := [][]float64{
		{1, 1.348520581}, {2, 2.524046187}, {3, 3.276944688}, {4, 4.735374498}, {5, 5.150291657},
	}
	slope := float64(0.981487046)
	correlation := float64(0.979228906)

	regression := newSimpleLinearRegression()
	for _, v := range variables {
		regression.AddPoint(v[0], v[1])
	}
	require.True(t, almostEqual(regression.slope, slope))
	require.True(t, almostEqual(regression.correlation, correlation))
}

func Test_LinearRegression_nonlinear_verify(t *testing.T) {
	variables := [][]float64{
		{1, 2}, {2, 4}, {3, 8}, {4, 16}, {5, 32},
	}

	regression := newSimpleLinearRegression()
	for _, v := range variables {
		regression.AddPoint(v[0], v[1])
	}
	require.Less(t, regression.correlation, 0.9)
}

const float64EqualityThreshold = 1e-8

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= float64EqualityThreshold
}
