package analyzers

import (
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/retryablehttp-go"
)

// Analyzer is an interface for all the analyzers
// that can be used for the fuzzer
type Analyzer interface {
	// Name returns the name of the analyzer
	Name() string
	// ApplyTransformation applies the transformation to the initial payload.
	ApplyInitialTransformation(data string, params map[string]interface{}) string
	// Analyze is the main function for the analyzer
	Analyze(options *Options) (bool, string, error)
}

// AnalyzerTemplate is the template for the analyzer
type AnalyzerTemplate struct {
	// description: |
	//   Name is the name of the analyzer to use
	// values:
	//   - time_delay
	Name string `json:"name" yaml:"name"`
	// description: |
	//   Parameters is the parameters for the analyzer
	//
	//   Parameters are different for each analyzer. For example, you can customize
	//   time_delay analyzer with sleep_duration, time_slope_error_range, etc. Refer
	//   to the docs for each analyzer to get an idea about parameters.
	Parameters map[string]interface{} `json:"parameters" yaml:"parameters"`
}

var (
	analyzers map[string]Analyzer
)

// RegisterAnalyzer registers a new analyzer
func RegisterAnalyzer(name string, analyzer Analyzer) {
	analyzers[name] = analyzer
}

// GetAnalyzer returns the analyzer for a given name
func GetAnalyzer(name string) Analyzer {
	return analyzers[name]
}

func init() {
	analyzers = make(map[string]Analyzer)
}

// Options contains the options for the analyzer
type Options struct {
	FuzzGenerated      fuzz.GeneratedRequest
	HttpClient         *retryablehttp.Client
	ResponseTimeDelay  time.Duration
	AnalyzerParameters map[string]interface{}
}

var (
	random = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// ApplyPayloadTransformations applies the payload transformations to the payload
// It supports the below payloads -
//   - [RANDNUM] => random number between 1000 and 9999
//   - [RANDSTR] => random string of 4 characters
func ApplyPayloadTransformations(value string) string {
	randomInt := GetRandomInteger()
	randomStr := randStringBytesMask(4)

	value = strings.ReplaceAll(value, "[RANDNUM]", strconv.Itoa(randomInt))
	value = strings.ReplaceAll(value, "[RANDSTR]", randomStr)
	return value
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func randStringBytesMask(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[random.Intn(len(letterBytes))]
	}
	return string(b)
}

// GetRandomInteger returns a random integer between 1000 and 9999
func GetRandomInteger() int {
	return random.Intn(9000) + 1000
}
