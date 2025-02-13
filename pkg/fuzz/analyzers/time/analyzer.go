package time

import (
	"fmt"
	"io"
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Analyzer is a time delay analyzer for the fuzzer
type Analyzer struct {
}

const (
	DefaultSleepDuration             = int(7)
	DefaultRequestsLimit             = int(4)
	DefaultTimeCorrelationErrorRange = float64(0.15)
	DefaultTimeSlopeErrorRange       = float64(0.30)
	DefaultLowSleepTimeSeconds       = float64(3)

	defaultSleepTimeDuration = 7 * time.Second
)

var _ analyzers.Analyzer = &Analyzer{}

func init() {
	analyzers.RegisterAnalyzer("time_delay", &Analyzer{})
}

// Name is the name of the analyzer
func (a *Analyzer) Name() string {
	return "time_delay"
}

// ApplyInitialTransformation applies the transformation to the initial payload.
//
// It supports the below payloads -
//   - [SLEEPTIME] => sleep_duration
//   - [INFERENCE] => Inference payload for time delay analyzer
//
// It also applies the payload transformations to the payload
// which includes [RANDNUM] and [RANDSTR]
func (a *Analyzer) ApplyInitialTransformation(data string, params map[string]interface{}) string {
	duration := DefaultSleepDuration
	if len(params) > 0 {
		if v, ok := params["sleep_duration"]; ok {
			duration, ok = v.(int)
			if !ok {
				duration = DefaultSleepDuration
				gologger.Warning().Msgf("Invalid sleep_duration parameter type, using default value: %d", duration)
			}
		}
	}
	data = strings.ReplaceAll(data, "[SLEEPTIME]", strconv.Itoa(duration))
	data = analyzers.ApplyPayloadTransformations(data)

	// Also support [INFERENCE] for the time delay analyzer
	if strings.Contains(data, "[INFERENCE]") {
		randInt := analyzers.GetRandomInteger()
		data = strings.ReplaceAll(data, "[INFERENCE]", fmt.Sprintf("%d=%d", randInt, randInt))
	}
	return data
}

func (a *Analyzer) parseAnalyzerParameters(params map[string]interface{}) (int, int, float64, float64, error) {
	requestsLimit := DefaultRequestsLimit
	sleepDuration := DefaultSleepDuration
	timeCorrelationErrorRange := DefaultTimeCorrelationErrorRange
	timeSlopeErrorRange := DefaultTimeSlopeErrorRange

	if len(params) == 0 {
		return requestsLimit, sleepDuration, timeCorrelationErrorRange, timeSlopeErrorRange, nil
	}
	var ok bool
	for k, v := range params {
		switch k {
		case "sleep_duration":
			sleepDuration, ok = v.(int)
		case "requests_limit":
			requestsLimit, ok = v.(int)
		case "time_correlation_error_range":
			timeCorrelationErrorRange, ok = v.(float64)
		case "time_slope_error_range":
			timeSlopeErrorRange, ok = v.(float64)
		}
		if !ok {
			return 0, 0, 0, 0, errors.Errorf("invalid parameter type for %s", k)
		}
	}
	return requestsLimit, sleepDuration, timeCorrelationErrorRange, timeSlopeErrorRange, nil
}

// Analyze is the main function for the analyzer
func (a *Analyzer) Analyze(options *analyzers.Options) (bool, string, error) {
	if options.ResponseTimeDelay < defaultSleepTimeDuration {
		return false, "", nil
	}

	// Parse parameters for this analyzer if any or use default values
	requestsLimit, sleepDuration, timeCorrelationErrorRange, timeSlopeErrorRange, err :=
		a.parseAnalyzerParameters(options.AnalyzerParameters)
	if err != nil {
		return false, "", err
	}

	reqSender := func(delay int) (float64, error) {
		gr := options.FuzzGenerated
		replaced := strings.ReplaceAll(gr.OriginalPayload, "[SLEEPTIME]", strconv.Itoa(delay))
		replaced = a.ApplyInitialTransformation(replaced, options.AnalyzerParameters)

		if err := gr.Component.SetValue(gr.Key, replaced); err != nil {
			return 0, errors.Wrap(err, "could not set value in component")
		}

		rebuilt, err := gr.Component.Rebuild()
		if err != nil {
			return 0, errors.Wrap(err, "could not rebuild request")
		}
		gologger.Verbose().Msgf("[%s] Sending request with %d delay for: %s", a.Name(), delay, rebuilt.URL.String())

		timeTaken, err := doHTTPRequestWithTimeTracing(rebuilt, options.HttpClient)
		if err != nil {
			return 0, errors.Wrap(err, "could not do request with time tracing")
		}
		return timeTaken, nil
	}

	// Check the baseline delay of the request by doing two requests
	baselineDelay, err := getBaselineDelay(reqSender)
	if err != nil {
		return false, "", err
	}

	matched, matchReason, err := checkTimingDependency(
		requestsLimit,
		sleepDuration,
		timeCorrelationErrorRange,
		timeSlopeErrorRange,
		baselineDelay,
		reqSender,
	)
	if err != nil {
		return false, "", err
	}
	if matched {
		return true, matchReason, nil
	}
	return false, "", nil
}

func getBaselineDelay(reqSender timeDelayRequestSender) (float64, error) {
	var delays []float64
	// Use zero or a very small delay to measure baseline
	for i := 0; i < 3; i++ {
		delay, err := reqSender(0)
		if err != nil {
			return 0, errors.Wrap(err, "could not get baseline delay")
		}
		delays = append(delays, delay)
	}

	var total float64
	for _, d := range delays {
		total += d
	}
	avg := total / float64(len(delays))
	return avg, nil
}

// doHTTPRequestWithTimeTracing does a http request with time tracing
func doHTTPRequestWithTimeTracing(req *retryablehttp.Request, httpclient *retryablehttp.Client) (float64, error) {
	var serverTime time.Duration
	var wroteRequest time.Time

	trace := &httptrace.ClientTrace{
		WroteHeaders: func() {
			wroteRequest = time.Now()
		},
		GotFirstResponseByte: func() {
			serverTime = time.Since(wroteRequest)
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := httpclient.Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "could not do request")
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, errors.Wrap(err, "could not read response body")
	}
	return serverTime.Seconds(), nil
}
