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
	delaySeconds = []int{3, 6, 9}
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

// AnalyzerInput is the input for an analyzer
type AnalyzerInput struct {
	Request   *retryablehttp.Request
	Component component.Component
	FinalArgs map[string]interface{}

	Key           string
	Value         string
	OriginalValue string
}

// Analyze analyzes the normalized request with a mutation
func (a *Analyzer) Analyze(httpclient *retryablehttp.Client, input *AnalyzerInput) (*Analysis, error) {
	averageRtt, err := a.createRequestBaseline(httpclient, input.Request, input.Component)
	if err != nil {
		return nil, errors.Wrap(err, "could not get request time baseline")
	}
	fmt.Printf("average rtt: %v\n", averageRtt)

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
func (a *Analyzer) delayFor(duration int, originalWaitTime float64, httpclient *retryablehttp.Client, input *AnalyzerInput) (string, *retryablehttp.Request, error) {
	fmt.Printf("got input: %+v\n", input)

	valueStr := strings.ReplaceAll(input.Value, delayPlaceholder, strconv.Itoa(duration))
	input.Component.SetValue(input.Key, valueStr)

	fmt.Printf("evaluated: %v\n", valueStr)

	defer func() {
		input.Component.SetValue(input.Key, input.OriginalValue)
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
