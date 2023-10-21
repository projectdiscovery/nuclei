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
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
)

// TimeDelayAnalyzer is an interface implemented by time delay analyzer
// It tries to control the delay in the request
// with means of a delay causing payload predictably a number
// of times.
//
// TODO: Improve and do more in-depth analysis for verification
// and offer configurable verification levels in order to control
// the quality of the results.
//
// Ported from: https://github.com/andresriancho/w3af/blob/master/w3af/core/controllers/delay_detection/exact_delay_controller.py
type TimeDelayAnalyzer struct{}

var _ Analyzer = &TimeDelayAnalyzer{}

var (
	// deltaPercent is 25% more/less than the original wait time
	deltaPercent = 0.25
	// delaySeconds is the list of timeouts to delay the request for
	delaySeconds = []int{3, 6, 9}
)

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
func (a *TimeDelayAnalyzer) Analyze(httpclient *retryablehttp.Client, input *AnalyzerInput) (*Analysis, error) {
	averageRtt, err := a.createRequestBaseline(httpclient, input.Request, input.Component)
	if err != nil {
		return nil, errors.Wrap(err, "could not get request time baseline")
	}

	var vulnReqMain *retryablehttp.Request
	delays := []string{}
	for _, delay := range delaySeconds {
		delayed, vulnReq, err := a.delayFor(delay, averageRtt, httpclient, input)
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
func (a *TimeDelayAnalyzer) delayFor(duration int, originalWaitTime float64, httpclient *retryablehttp.Client, input *AnalyzerInput) (string, *retryablehttp.Request, error) {
	fmt.Printf("got input: %+v\n", input)

	valueStr := strings.ReplaceAll(input.Value, delayPlaceholder, strconv.Itoa(duration))
	if err := input.Component.SetValue(input.Key, valueStr); err != nil {
		return "", nil, err
	}

	fmt.Printf("evaluated: %v\n", valueStr)

	defer func() {
		err := input.Component.SetValue(input.Key, input.OriginalValue)
		if err != nil {
			gologger.Verbose().Msgf("analyzer: timedelay: failed to set value: %s", err)
		}
	}()

	mutation, err := input.Component.Rebuild()
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
	upperBound := (originalWaitTime + delta + float64(duration)*2) * 2
	lowerBound := float64(duration)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(upperBound)*time.Second)
	defer cancel()

	mutation = mutation.WithContext(ctx)
	responseDelay, err := doHTTPRequestWithTimeTracing(httpclient, mutation)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return "", nil, errors.Wrap(err, "could not do request with time tracing")
	}

	fmt.Printf("response delay: %v\n", responseDelay)

	if math.Ceil(responseDelay) >= float64(lowerBound) {
		return fmt.Sprintf("responseDelay %.2f greater than lowerBound %.2f (upperBound: %.2f)", responseDelay, lowerBound, upperBound), mutation, nil
	}
	return "", nil, nil
}

const defaultInitializationCount = 2

// createRequestBaseline creates a new time baseline from a request
// by repeating it with a blank mutation `defaultInitializationCount` times.
func (a *TimeDelayAnalyzer) createRequestBaseline(httpclient *retryablehttp.Client, req *retryablehttp.Request, component component.Component) (float64, error) {
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
