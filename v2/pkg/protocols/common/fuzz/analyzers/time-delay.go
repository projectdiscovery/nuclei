package analyzers

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/fuzz/component"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Analyzer is an interface implemented by time delay analyzer
// It tries to control the delay in the request
// with means of a delay causing payload predictably a number
// of times.
//
// Ported from: https://github.com/andresriancho/w3af/blob/master/w3af/core/controllers/delay_detection/exact_delay_controller.py
type Analyzer struct{}

var (
	// deltaPercent is 25% more/less than the original wait time
	deltaPercent = 0.25
	// delaySeconds is the list of timeouts to delay the request for
	delaySeconds = []int{8, 4, 9}
)

// Analysis is a time delay analysis result
type Analysis struct {
	Matched  bool     `json:"matched"`
	Reasons  []string `json:"reasons"`
	Analyzer string   `json:"analyzer"`

	VulnerableRequest *retryablehttp.Request `json:"-"`
}

// doHTTPRequestWithTimeTracing does a http request with time tracing
func doHTTPRequestWithTimeTracing(httpclient *retryablehttp.Client, req *retryablehttp.Request) (float64, error) {
	var ttfb time.Duration
	var start time.Time

	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { ttfb = time.Since(start) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()
	resp, err := httpclient.Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "could not do request")
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, errors.Wrap(err, "could not read response body")
	}
	return ttfb.Seconds(), nil
}

// Analyze analyzes the normalized request with a mutation
func (a *Analyzer) Analyze(httpclient *retryablehttp.Client, req *retryablehttp.Request, component component.Component, finalMap map[string]interface{}) (*Analysis, error) {
	averageRtt, err := a.createRequestBaseline(httpclient, req, component)
	if err != nil {
		return nil, errors.Wrap(err, "could not get request time baseline")
	}

	var vulnReqMain *retryablehttp.Request
	delays := []string{}
	for _, delay := range delaySeconds {
		delayed, vulnReq, err := a.delayFor(delay, averageRtt, httpclient, req, finalMap, component)
		if err != nil {
			return nil, errors.Wrap(err, "could not delay the request for duration")
		}
		// We've not delayed so return
		if delayed == "" {
			return nil, nil
		}
		if vulnReqMain == nil && vulnReq != nil {
			vulnReqMain = vulnReq
		}
		delays = append(delays, delayed)
	}
	if len(delays) == 0 {
		return nil, nil
	}
	if len(delays) == len(delaySeconds) {
		return &Analysis{
			Matched:           true,
			Reasons:           delays,
			Analyzer:          "time-delay",
			VulnerableRequest: vulnReqMain,
		}, nil
	}
	return nil, nil
}

var delayPlaceholder = "{{delay}}"

// delayFor tries delaying a response for duration seconds
func (a *Analyzer) delayFor(duration int, originalWaitTime float64, httpclient *retryablehttp.Client, req *retryablehttp.Request, payloads map[string]interface{}, component component.Component) (string, *retryablehttp.Request, error) {
	keysToValues := make(map[string]interface{})
	component.Iterate(func(key string, value interface{}) {
		valueStr := types.ToString(value)

		if !strings.Contains(valueStr, delayPlaceholder) {
			return
		}

		keysToValues[key] = value
		// Replace the placeholder with the duration
		valueStr = strings.ReplaceAll(valueStr, delayPlaceholder, strconv.Itoa(duration))
		component.SetValue(key, valueStr)
	})
	if len(keysToValues) == 0 {
		return "", nil, nil
	}
	defer func() {
		// Reset the values back to original
		for key, value := range keysToValues {
			component.SetValue(key, types.ToString(value))
		}
	}()

	mutation, err := component.Rebuild()
	if err != nil {
		return "", nil, errors.Wrap(err, "could not rebuild component")
	}

	// Set the upper and lower bounds
	delta := originalWaitTime * deltaPercent

	// Upper bound is the highest number we'll wait for a response, it
	// doesn't mean that it is the highest delay that might happen on
	// the application.
	//
	// It is set to a calculation of originalRequestDuration + delta + duration * 2.
	// while the lowest acceptable duration is the delay seconds itself.
	upperBound := originalWaitTime + delta + float64(duration)*2
	lowerBound := float64(duration)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(upperBound)*time.Second)
	defer cancel()

	mutation = mutation.WithContext(ctx)
	responseDelay, err := doHTTPRequestWithTimeTracing(httpclient, mutation)
	if err != nil {
		return "", nil, errors.Wrap(err, "could not do request with time tracing")
	}

	if math.Ceil(responseDelay) >= float64(lowerBound) {
		return fmt.Sprintf("responseDelay %.2f greater than lowerBound %.2f (upperBound: %.2f)", responseDelay, lowerBound, upperBound), mutation, nil
	}
	return "", nil, nil
}

const defaultInitializationCount = 2

// createRequestBaseline creates a new time baseline from a request
// by repeating it with a blank mutation `defaultInitializationCount` times.
func (a *Analyzer) createRequestBaseline(httpclient *retryablehttp.Client, req *retryablehttp.Request, component component.Component) (float64, error) {
	rttsSum := float64(0)
	for i := 0; i < defaultInitializationCount; i++ {
		duration, err := doHTTPRequestWithTimeTracing(httpclient, req)
		if err != nil {
			return 0, err
		}
		rttsSum = rttsSum + duration
	}
	// TODO:(iceman) Check if there's large variance in time durations
	// for each of the request.
	// TODO:(iceman) We also need to cache all these time checking calls
	// only once every few durations since they're quite intensive. (w3af uses caching)
	// Return the average of all the durations to get an accurate measurement
	return float64(rttsSum / float64(defaultInitializationCount)), nil
}
