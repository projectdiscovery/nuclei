// Package time implements a time delay analyzer using linear
// regression heuristics inspired from ZAP to discover time
// based issues.
//
// The approach is the one used in ZAP for timing based checks.
// Advantages of this approach are many compared to the old approach of
// heuristics of sleep time.
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
)

type timeDelayRequestSender func(delay int) (float64, error)

// checkTimingDependency checks the timing dependency for a given request
//
// It alternates and sends first a high request, then a low request. Each time
// it checks if the delay of the application can be predictably controlled.
func checkTimingDependency(
	requestsLimit int,
	highSleepTimeSeconds int,
	correlationErrorRange float64,
	slopeErrorRange float64,
	requestSender timeDelayRequestSender,
) (bool, string, error) {
	if requestsLimit < 2 {
		return false, "", errors.New("requests limit should be at least 2")
	}

	regression := newSimpleLinearRegression()
	requestsLeft := requestsLimit

	for {
		if requestsLeft <= 0 {
			break
		}

		isCorrelationPossible, err := sendRequestAndTestConfidence(regression, highSleepTimeSeconds, requestSender)
		if err != nil {
			return false, "", err
		}
		if !isCorrelationPossible {
			return false, "", nil
		}

		isCorrelationPossible, err = sendRequestAndTestConfidence(regression, 1, requestSender)
		if err != nil {
			return false, "", err
		}
		if !isCorrelationPossible {
			return false, "", nil
		}
		requestsLeft = requestsLeft - 2
	}

	result := regression.IsWithinConfidence(correlationErrorRange, 1.0, slopeErrorRange)
	if result {
		resultReason := fmt.Sprintf(
			"[time_delay] made %d requests successfully, with a regression slope of %.2f and correlation %.2f",
			requestsLimit,
			regression.slope,
			regression.correlation,
		)
		return result, resultReason, nil
	}
	return result, "", nil
}

// sendRequestAndTestConfidence sends a request and tests the confidence of delay
func sendRequestAndTestConfidence(
	regression *simpleLinearRegression,
	delay int,
	requestSender timeDelayRequestSender,
) (bool, error) {
	delayReceived, err := requestSender(delay)
	if err != nil {
		return false, err
	}

	if delayReceived < float64(delay) {
		return false, nil
	}

	regression.AddPoint(float64(delay), delayReceived)

	if !regression.IsWithinConfidence(0.3, 1.0, 0.5) {
		return false, nil
	}
	return true, nil
}

// simpleLinearRegression is a simple linear regression model that can be updated at runtime.
// It is based on the same algorithm in ZAP for doing timing checks.
type simpleLinearRegression struct {
	count          float64
	independentSum float64
	dependentSum   float64

	// Variances
	independentVarianceN float64
	dependentVarianceN   float64
	sampleCovarianceN    float64

	slope       float64
	intercept   float64
	correlation float64
}

func newSimpleLinearRegression() *simpleLinearRegression {
	return &simpleLinearRegression{
		slope:       1,
		correlation: 1,
	}
}

func (o *simpleLinearRegression) AddPoint(x, y float64) {
	independentResidualAdjustment := x - o.independentSum/o.count
	dependentResidualAdjustment := y - o.dependentSum/o.count

	o.count += 1
	o.independentSum += x
	o.dependentSum += y

	if math.IsNaN(independentResidualAdjustment) {
		return
	}

	independentResidual := x - o.independentSum/o.count
	dependentResidual := y - o.dependentSum/o.count

	o.independentVarianceN += independentResidual * independentResidualAdjustment
	o.dependentVarianceN += dependentResidual * dependentResidualAdjustment
	o.sampleCovarianceN += independentResidual * dependentResidualAdjustment

	o.slope = o.sampleCovarianceN / o.independentVarianceN
	o.correlation = o.slope * math.Sqrt(o.independentVarianceN/o.dependentVarianceN)
	o.correlation *= o.correlation

	// NOTE: zap had the reverse formula, changed it to the correct one
	// for intercept. Verify if this is correct.
	o.intercept = o.dependentSum/o.count - o.slope*(o.independentSum/o.count)
	if math.IsNaN(o.correlation) {
		o.correlation = 1
	}
}

func (o *simpleLinearRegression) Predict(x float64) float64 {
	return o.slope*x + o.intercept
}

func (o *simpleLinearRegression) IsWithinConfidence(correlationErrorRange float64, expectedSlope float64, slopeErrorRange float64,
) bool {
	return o.correlation > 1.0-correlationErrorRange &&
		math.Abs(expectedSlope-o.slope) < slopeErrorRange
}
