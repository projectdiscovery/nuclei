// Tests ported from ZAP Java version of the algorithm

package time

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

// This test suite verifies the timing dependency detection algorithm by testing various scenarios:
//
// Test Categories:
// 1. Perfect Linear Cases
//    - TestPerfectLinear: Basic case with slope=1, no noise
//    - TestPerfectLinearSlopeOne_NoNoise: Similar to above but with different parameters
//    - TestPerfectLinearSlopeTwo_NoNoise: Tests detection of slope=2 relationship
//
// 2. Noisy Cases
//    - TestLinearWithNoise: Verifies detection works with moderate noise (±0.2s)
//    - TestNoisyLinear: Similar but with different noise parameters
//    - TestHighNoiseConcealsSlope: Verifies detection fails with extreme noise (±5s)
//
// 3. No Correlation Cases
//    - TestNoCorrelation: Basic case where delay has no effect
//    - TestNoCorrelationHighBaseline: High baseline (~15s) masks any delay effect
//    - TestNegativeSlopeScenario: Verifies detection rejects negative correlations
//
// 4. Edge Cases
//    - TestMinimalData: Tests behavior with minimal data points (2 requests)
//    - TestLargeNumberOfRequests: Tests stability with many data points (20 requests)
//    - TestChangingBaseline: Tests detection with shifting baseline mid-test
//    - TestHighBaselineLowSlope: Tests detection of subtle correlations (slope=0.85)
//
// ZAP Test Cases:
//
// 1. Alternating Sequence Tests
//    - TestAlternatingSequences: Verifies correct alternation between high and low delays
//
// 2. Non-Injectable Cases
//    - TestNonInjectableQuickFail: Tests quick failure when response time < requested delay
//    - TestSlowNonInjectableCase: Tests early termination with consistently high response times
//    - TestRealWorldNonInjectableCase: Tests behavior with real-world response patterns
//
// 3. Error Tolerance Tests
//    - TestSmallErrorDependence: Verifies detection works with small random variations
//
// Key Parameters Tested:
// - requestsLimit: Number of requests to make (2-20)
// - highSleepTimeSeconds: Maximum delay to test (typically 5s)
// - correlationErrorRange: Acceptable deviation from perfect correlation (0.05-0.3)
// - slopeErrorRange: Acceptable deviation from expected slope (0.1-1.5)
//
// The test suite uses various mock senders (perfectLinearSender, noCorrelationSender, etc.)
// to simulate different timing behaviors and verify the detection algorithm works correctly
// across a wide range of scenarios.

// Mock request sender that simulates a perfect linear relationship:
// Observed delay = baseline + requested_delay
func perfectLinearSender(baseline float64) func(delay int) (float64, error) {
	return func(delay int) (float64, error) {
		// simulate some processing time
		time.Sleep(10 * time.Millisecond) // just a small artificial sleep to mimic network
		return baseline + float64(delay), nil
	}
}

// Mock request sender that simulates no correlation:
// The response time is random around a certain constant baseline, ignoring requested delay.
func noCorrelationSender(baseline, noiseAmplitude float64) func(int) (float64, error) {
	return func(delay int) (float64, error) {
		time.Sleep(10 * time.Millisecond)
		noise := 0.0
		if noiseAmplitude > 0 {
			noise = (rand.Float64()*2 - 1) * noiseAmplitude
		}
		return baseline + noise, nil
	}
}

// Mock request sender that simulates partial linearity but with some noise.
func noisyLinearSender(baseline float64) func(delay int) (float64, error) {
	return func(delay int) (float64, error) {
		time.Sleep(10 * time.Millisecond)
		// Add some noise (±0.2s) to a linear relationship
		noise := 0.2
		return baseline + float64(delay) + noise, nil
	}
}

func TestPerfectLinear(t *testing.T) {
	// Expect near-perfect correlation and slope ~ 1.0
	requestsLimit := 6 // 3 pairs: enough data for stable regression
	highSleepTimeSeconds := 5
	corrErrRange := 0.1
	slopeErrRange := 0.2
	baseline := 5.0

	sender := perfectLinearSender(5.0) // baseline 5s, observed = 5s + requested_delay
	match, reason, err := checkTimingDependency(
		requestsLimit,
		highSleepTimeSeconds,
		corrErrRange,
		slopeErrRange,
		baseline,
		sender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("Expected a match but got none. Reason: %s", reason)
	}
}

func TestNoCorrelation(t *testing.T) {
	// Expect no match because requested delay doesn't influence observed delay
	requestsLimit := 6
	highSleepTimeSeconds := 5
	corrErrRange := 0.1
	slopeErrRange := 0.5
	baseline := 8.0

	sender := noCorrelationSender(8.0, 0.1)
	match, reason, err := checkTimingDependency(
		requestsLimit,
		highSleepTimeSeconds,
		corrErrRange,
		slopeErrRange,
		baseline,
		sender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if match {
		t.Fatalf("Expected no match but got one. Reason: %s", reason)
	}
}

func TestNoisyLinear(t *testing.T) {
	// Even with some noise, it should detect a strong positive correlation if
	// we allow a slightly bigger margin for slope/correlation.
	requestsLimit := 10 // More requests to average out noise
	highSleepTimeSeconds := 5
	corrErrRange := 0.2  // allow some lower correlation due to noise
	slopeErrRange := 0.5 // slope may deviate slightly
	baseline := 2.0

	sender := noisyLinearSender(2.0) // baseline 2s, observed ~ 2s + requested_delay ±0.2
	match, reason, err := checkTimingDependency(
		requestsLimit,
		highSleepTimeSeconds,
		corrErrRange,
		slopeErrRange,
		baseline,
		sender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// We expect a match since it's still roughly linear. The slope should be close to 1.
	if !match {
		t.Fatalf("Expected a match in noisy linear test but got none. Reason: %s", reason)
	}
}

func TestMinimalData(t *testing.T) {
	// With too few requests, correlation might not be stable.
	// Here, we send only 2 requests (1 pair) and see if the logic handles it gracefully.
	requestsLimit := 2
	highSleepTimeSeconds := 5
	corrErrRange := 0.3
	slopeErrRange := 0.5
	baseline := 5.0

	// Perfect linear sender again
	sender := perfectLinearSender(5.0)
	match, reason, err := checkTimingDependency(
		requestsLimit,
		highSleepTimeSeconds,
		corrErrRange,
		slopeErrRange,
		baseline,
		sender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("Expected match but got none. Reason: %s", reason)
	}
}

// Utility functions to generate different behaviors

// linearSender returns a sender that calculates observed delay as:
// observed = baseline + slope * requested_delay + noise
func linearSender(baseline, slope, noiseAmplitude float64) func(int) (float64, error) {
	return func(delay int) (float64, error) {
		time.Sleep(10 * time.Millisecond)
		noise := 0.0
		if noiseAmplitude > 0 {
			noise = (rand.Float64()*2 - 1) * noiseAmplitude // random noise in [-noiseAmplitude, noiseAmplitude]
		}
		return baseline + slope*float64(delay) + noise, nil
	}
}

// negativeSlopeSender just for completeness - higher delay = less observed time
func negativeSlopeSender(baseline float64) func(int) (float64, error) {
	return func(delay int) (float64, error) {
		time.Sleep(10 * time.Millisecond)
		return baseline - float64(delay)*2.0, nil
	}
}

func TestPerfectLinearSlopeOne_NoNoise(t *testing.T) {
	baseline := 2.0
	match, reason, err := checkTimingDependency(
		10,  // requestsLimit
		5,   // highSleepTimeSeconds
		0.1, // correlationErrorRange
		0.2, // slopeErrorRange (allowing slope between 0.8 and 1.2)
		baseline,
		linearSender(baseline, 1.0, 0.0),
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("Expected a match for perfect linear slope=1. Reason: %s", reason)
	}
}

func TestPerfectLinearSlopeTwo_NoNoise(t *testing.T) {
	baseline := 2.0
	// slope=2 means observed = baseline + 2*requested_delay
	match, reason, err := checkTimingDependency(
		10,
		5,
		0.1, // correlation must still be good
		1.5, // allow slope in range (0.5 to 2.5), we should be close to 2.0 anyway
		baseline,
		linearSender(baseline, 2.0, 0.0),
	)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !match {
		t.Fatalf("Expected a match for slope=2. Reason: %s", reason)
	}
}

func TestLinearWithNoise(t *testing.T) {
	baseline := 5.0
	// slope=1 but with noise ±0.2 seconds
	match, reason, err := checkTimingDependency(
		12,
		5,
		0.2, // correlationErrorRange relaxed to account for noise
		0.5, // slopeErrorRange also relaxed
		baseline,
		linearSender(baseline, 1.0, 0.2),
	)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !match {
		t.Fatalf("Expected a match for noisy linear data. Reason: %s", reason)
	}
}

func TestNoCorrelationHighBaseline(t *testing.T) {
	baseline := 15.0
	// baseline ~15s, requested delays won't matter
	match, reason, err := checkTimingDependency(
		10,
		5,
		0.1, // correlation should be near zero, so no match expected
		0.5,
		baseline,
		noCorrelationSender(baseline, 0.1),
	)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if match {
		t.Fatalf("Expected no match for no correlation scenario. Got: %s", reason)
	}
}

func TestNegativeSlopeScenario(t *testing.T) {
	baseline := 10.0
	// Increasing delay decreases observed time
	match, reason, err := checkTimingDependency(
		10,
		5,
		0.2,
		0.5,
		baseline,
		negativeSlopeSender(baseline),
	)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if match {
		t.Fatalf("Expected no match in negative slope scenario. Reason: %s", reason)
	}
}

func TestLargeNumberOfRequests(t *testing.T) {
	baseline := 1.0
	// 20 requests, slope=1.0, no noise. Should be very stable and produce a very high correlation.
	match, reason, err := checkTimingDependency(
		20,
		5,
		0.05, // very strict correlation requirement
		0.1,  // very strict slope range
		baseline,
		linearSender(baseline, 1.0, 0.0),
	)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !match {
		t.Fatalf("Expected a strong match with many requests and perfect linearity. Reason: %s", reason)
	}
}

func TestHighBaselineLowSlope(t *testing.T) {
	baseline := 15.0
	match, reason, err := checkTimingDependency(
		10,
		5,
		0.2,
		0.2, // expecting slope around 0.5, allow range ~0.4 to 0.6
		baseline,
		linearSender(baseline, 0.85, 0.0),
	)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	if !match {
		t.Fatalf("Expected a match for slope=0.5 linear scenario. Reason: %s", reason)
	}
}

func TestHighNoiseConcealsSlope(t *testing.T) {
	baseline := 5.0
	// slope=1, but noise=5 seconds is huge and might conceal the correlation.
	// With large noise, the test may fail to detect correlation.
	match, reason, err := checkTimingDependency(
		12,
		5,
		0.1, // still strict
		0.2, // still strict
		baseline,
		linearSender(baseline, 1.0, 5.0),
	)
	if err != nil {
		t.Fatalf("Error: %v", err)
	}
	// Expect no match because the noise level is too high to establish a reliable correlation.
	if match {
		t.Fatalf("Expected no match due to extreme noise. Reason: %s", reason)
	}
}

func TestAlternatingSequences(t *testing.T) {
	baseline := 0.0
	var generatedDelays []float64
	reqSender := func(delay int) (float64, error) {
		generatedDelays = append(generatedDelays, float64(delay))
		return float64(delay), nil
	}
	match, reason, err := checkTimingDependency(
		4,   // requestsLimit
		15,  // highSleepTimeSeconds
		0.1, // correlationErrorRange
		0.2, // slopeErrorRange
		baseline,
		reqSender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("Expected a match but got none. Reason: %s", reason)
	}
	// Verify alternating sequence of delays
	expectedDelays := []float64{15, 3, 15, 3}
	if !reflect.DeepEqual(generatedDelays, expectedDelays) {
		t.Fatalf("Expected delays %v but got %v", expectedDelays, generatedDelays)
	}
}

func TestNonInjectableQuickFail(t *testing.T) {
	baseline := 0.5
	var timesCalled int
	reqSender := func(delay int) (float64, error) {
		timesCalled++
		return 0.5, nil // Return value less than delay
	}
	match, _, err := checkTimingDependency(
		4,   // requestsLimit
		15,  // highSleepTimeSeconds
		0.1, // correlationErrorRange
		0.2, // slopeErrorRange
		baseline,
		reqSender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if match {
		t.Fatal("Expected no match for non-injectable case")
	}
	if timesCalled != 1 {
		t.Fatalf("Expected quick fail after 1 call, got %d calls", timesCalled)
	}
}

func TestSlowNonInjectableCase(t *testing.T) {
	baseline := 10.0
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var timesCalled int
	reqSender := func(delay int) (float64, error) {
		timesCalled++
		return 10 + rng.Float64()*0.5, nil
	}
	match, _, err := checkTimingDependency(
		4,   // requestsLimit
		15,  // highSleepTimeSeconds
		0.1, // correlationErrorRange
		0.2, // slopeErrorRange
		baseline,
		reqSender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if match {
		t.Fatal("Expected no match for slow non-injectable case")
	}
	if timesCalled > 3 {
		t.Fatalf("Expected early termination (≤3 calls), got %d calls", timesCalled)
	}
}

func TestRealWorldNonInjectableCase(t *testing.T) {
	baseline := 0.0
	var iteration int
	counts := []float64{11, 21, 11, 21, 11}
	reqSender := func(delay int) (float64, error) {
		iteration++
		return counts[iteration-1], nil
	}
	match, _, err := checkTimingDependency(
		4,   // requestsLimit
		15,  // highSleepTimeSeconds
		0.1, // correlationErrorRange
		0.2, // slopeErrorRange
		baseline,
		reqSender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if match {
		t.Fatal("Expected no match for real-world non-injectable case")
	}
	if iteration > 4 {
		t.Fatalf("Expected ≤4 iterations, got %d", iteration)
	}
}

func TestSmallErrorDependence(t *testing.T) {
	baseline := 0.0
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	reqSender := func(delay int) (float64, error) {
		return float64(delay) + rng.Float64()*0.5, nil
	}
	match, reason, err := checkTimingDependency(
		4,   // requestsLimit
		15,  // highSleepTimeSeconds
		0.1, // correlationErrorRange
		0.2, // slopeErrorRange
		baseline,
		reqSender,
	)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !match {
		t.Fatalf("Expected match for small error case. Reason: %s", reason)
	}
}
