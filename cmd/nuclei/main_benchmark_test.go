package main_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

var (
	projectPath string
	targetURL   string
)

func TestMain(m *testing.M) {
	// Set up

	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	os.Setenv("DISABLE_STDOUT", "true")

	var err error

	projectPath, err = os.MkdirTemp("", "nuclei-benchmark-")
	if err != nil {
		panic(err)
	}

	dummyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	targetURL = dummyServer.URL

	// Execute tests

	exitCode := m.Run()

	// Tear down

	dummyServer.Close()
	_ = os.RemoveAll(projectPath)
	os.Unsetenv("DISABLE_STDOUT")

	os.Exit(exitCode)
}

func getDefaultOptions() *types.Options {
	return &types.Options{
		RemoteTemplateDomainList:   []string{"cloud.projectdiscovery.io"},
		ProjectPath:                projectPath,
		StatsInterval:              5,
		MetricsPort:                9092,
		MaxHostError:               30,
		NoHostErrors:               true,
		BulkSize:                   25,
		TemplateThreads:            25,
		HeadlessBulkSize:           10,
		HeadlessTemplateThreads:    10,
		Timeout:                    10,
		Retries:                    1,
		RateLimit:                  150,
		RateLimitDuration:          time.Duration(time.Second),
		RateLimitMinute:            0,
		PageTimeout:                20,
		InteractionsCacheSize:      5000,
		InteractionsPollDuration:   5,
		InteractionsEviction:       60,
		InteractionsCoolDownPeriod: 5,
		MaxRedirects:               10,
		Silent:                     true,
		VarDumpLimit:               255,
		JSONRequests:               true,
		StoreResponseDir:           "output",
		InputFileMode:              "list",
		ResponseReadSize:           0,
		ResponseSaveSize:           1048576,
		InputReadTimeout:           time.Duration(3 * time.Minute),
		UncoverField:               "ip:port",
		UncoverLimit:               100,
		UncoverRateLimit:           60,
		ScanStrategy:               "auto",
		FuzzAggressionLevel:        "low",
		FuzzParamFrequency:         10,
		TeamID:                     "none",
		JsConcurrency:              120,
		PayloadConcurrency:         25,
		ProbeConcurrency:           50,
		LoadHelperFileFunction:     types.DefaultOptions().LoadHelperFileFunction,
		// DialerKeepAlive:            time.Duration(0),
		// DASTServerAddress:          "localhost:9055",
	}
}

func runEnumBenchmark(b *testing.B, options *types.Options) {
	runner.ParseOptions(options)

	nucleiRunner, err := runner.New(options)
	if err != nil {
		b.Fatalf("failed to create runner: %s", err)
	}
	defer nucleiRunner.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if err := nucleiRunner.RunEnumeration(); err != nil {
			b.Fatalf("%s failed: %s", b.Name(), err)
		}
	}
}

func BenchmarkRunEnumeration(b *testing.B) {
	// Default case: run enumeration with default options == all nuclei-templates
	// b.Run("Default", func(b *testing.B) {
	// 	options := getDefaultOptions()
	// 	options.Targets = []string{targetURL}

	// 	runEnumBenchmark(b, options)
	// })

	// Case: https://github.com/projectdiscovery/nuclei/pull/6258
	b.Run("Multiproto", func(b *testing.B) {
		options := getDefaultOptions()
		options.Targets = []string{targetURL}
		options.Templates = []string{"./cmd/nuclei/testdata/benchmark/multiproto/"}

		runEnumBenchmark(b, options)
	})
}
