// Package time implements a time delay analyzer using linear
// regression heuristics inspired from ZAP to discover time
// based issues.
//
// The approach is the one used in ZAP for timing based checks.
// Advantages of this approach are many compared to the old approach of
// heuristics of sleep time.
//
// NOTE: This algorithm has been heavily modified after being introduced
// in nuclei. Now the logic has sever bug fixes and improvements and
// has been evolving to be more stable.
//
// As we are building a statistical model, we can predict if the delay
// is random or not very quickly. Also, the payloads are alternated to send
// a very high sleep and a very low sleep. This way the comparison is
// faster to eliminate negative cases. Only legitimate cases are sent for
// more verification.
//
// For more details on the algorithm, follow the links below:
// - https://groups.google.com/g/zaproxy-develop/c/KGSkNHlLtqk
// - https://github.com/zaproxy/zap-extensions/pull/5053
//
// This file has been implemented from its original version. It was originally licensed under the Apache License 2.0 (see LICENSE file for details).
// The original algorithm is implemented in ZAP Active Scanner.
package time

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

type timeDelayRequestSender func(delay int) (float64, error)

// requestsSentMetadata is used to store the delay requested
// and delay received for each request
type requestsSentMetadata struct {
	delay         int
	delayReceived float64
}

// checkTimingDependency checks the timing dependency for a given request
//
// It alternates and sends first a high request, then a low request. Each time
// it checks if the delay of the application can be predictably controlled.
func checkTimingDependency(
	requestsLimit int,
	highSleepTimeSeconds int,
	correlationErrorRange float64,
	slopeErrorRange float64,
	baselineDelay float64,
	requestSender timeDelayRequestSender,
) (bool, string, error) {
	if requestsLimit < 2 {
		return false, "", errors.New("requests limit should be at least 2")
	}

	regression := newSimpleLinearRegression()
	requestsLeft := requestsLimit

	var requestsSent []requestsSentMetadata
	for {
		if requestsLeft <= 0 {
			break
		}

		isCorrelationPossible, delayRecieved, err := sendRequestAndTestConfidence(regression, highSleepTimeSeconds, requestSender, baselineDelay)
		if err != nil {
			return false, "", err
		}
		if !isCorrelationPossible {
			return false, "", nil
		}
		// Check the delay is greater than baseline by seconds requested
		if delayRecieved < baselineDelay+float64(highSleepTimeSeconds)*0.8 {
			return false, "", nil
		}
		requestsSent = append(requestsSent, requestsSentMetadata{
			delay:         highSleepTimeSeconds,
			delayReceived: delayRecieved,
		})

		isCorrelationPossibleSecond, delayRecievedSecond, err := sendRequestAndTestConfidence(regression, int(DefaultLowSleepTimeSeconds), requestSender, baselineDelay)
		if err != nil {
			return false, "", err
		}
		if !isCorrelationPossibleSecond {
			return false, "", nil
		}
		if delayRecievedSecond < baselineDelay+float64(DefaultLowSleepTimeSeconds)*0.8 {
			return false, "", nil
		}
		requestsLeft = requestsLeft - 2

		requestsSent = append(requestsSent, requestsSentMetadata{
			delay:         int(DefaultLowSleepTimeSeconds),
			delayReceived: delayRecievedSecond,
		})
	}

	result := regression.IsWithinConfidence(correlationErrorRange, 1.0, slopeErrorRange)
	if result {
		var resultReason strings.Builder
		resultReason.WriteString(fmt.Sprintf(
			"[time_delay] made %d requests (baseline: %.2fs) successfully, with a regression slope of %.2f and correlation %.2f",
			requestsLimit,
			baselineDelay,
			regression.slope,
			regression.correlation,
		))
		for _, request := range requestsSent {
			resultReason.WriteString(fmt.Sprintf("\n - delay: %ds, delayReceived: %fs", request.delay, request.delayReceived))
		}
		return result, resultReason.String(), nil
	}
	return result, "", nil
}

// sendRequestAndTestConfidence sends a request and tests the confidence of delay
func sendRequestAndTestConfidence(
	regression *simpleLinearRegression,
	delay int,
	requestSender timeDelayRequestSender,
	baselineDelay float64,
) (bool, float64, error) {
	delayReceived, err := requestSender(delay)
	if err != nil {
		return false, 0, err
	}

	if delayReceived < float64(delay) {
		return false, 0, nil
	}

	regression.AddPoint(float64(delay), delayReceived-baselineDelay)

	if !regression.IsWithinConfidence(0.3, 1.0, 0.5) {
		return false, delayReceived, nil
	}
	return true, delayReceived, nil
}

type simpleLinearRegression struct {
	count float64

	sumX  float64
	sumY  float64
	sumXX float64
	sumYY float64
	sumXY float64

	slope       float64
	intercept   float64
	correlation float64
}

func newSimpleLinearRegression() *simpleLinearRegression {
	return &simpleLinearRegression{
		// Start everything at zero until we have data
		slope:       0.0,
		intercept:   0.0,
		correlation: 0.0,
	}
}

func (o *simpleLinearRegression) AddPoint(x, y float64) {
	o.count += 1
	o.sumX += x
	o.sumY += y
	o.sumXX += x * x
	o.sumYY += y * y
	o.sumXY += x * y

	// Need at least two points for meaningful calculation
	if o.count < 2 {
		return
	}

	n := o.count
	meanX := o.sumX / n
	meanY := o.sumY / n

	// Compute sample variances and covariance
	varX := (o.sumXX - n*meanX*meanX) / (n - 1)
	varY := (o.sumYY - n*meanY*meanY) / (n - 1)
	covXY := (o.sumXY - n*meanX*meanY) / (n - 1)

	// If varX is zero, slope cannot be computed meaningfully.
	// This would mean all X are the same, so handle that edge case.
	if varX == 0 {
		o.slope = 0.0
		o.intercept = meanY // Just the mean
		o.correlation = 0.0 // No correlation since all X are identical
		return
	}

	o.slope = covXY / varX
	o.intercept = meanY - o.slope*meanX

	// If varX or varY are zero, we cannot compute correlation properly.
	if varX > 0 && varY > 0 {
		o.correlation = covXY / (math.Sqrt(varX) * math.Sqrt(varY))
	} else {
		o.correlation = 0.0
	}
}

func (o *simpleLinearRegression) Predict(x float64) float64 {
	return o.slope*x + o.intercept
}

func (o *simpleLinearRegression) IsWithinConfidence(correlationErrorRange float64, expectedSlope float64, slopeErrorRange float64) bool {
	if o.count < 2 {
		return true
	}
	// Check if slope is within error range of expected slope
	// Also consider cases where slope is approximately 2x of expected slope
	// as this can happen with time-based responses
	slopeDiff := math.Abs(expectedSlope - o.slope)
	slope2xDiff := math.Abs(expectedSlope*2 - o.slope)
	if slopeDiff > slopeErrorRange && slope2xDiff > slopeErrorRange {
		return false
	}
	return o.correlation > 1.0-correlationErrorRange
}
