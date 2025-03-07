package main_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func BenchmarkRunEnumeration(b *testing.B) {
	dummyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer dummyServer.Close()

	options := &types.Options{
		RemoteTemplateDomainList: goflags.StringSlice{
			"cloud.projectdiscovery.io",
		},
		ProjectPath:                "/tmp",
		Targets:                    goflags.StringSlice{dummyServer.URL},
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

	runner.ParseOptions(options)

	// Disable logging to reduce benchmark noise.
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	nucleiRunner, err := runner.New(options)
	if err != nil {
		b.Fatalf("failed to create runner: %s", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if err := nucleiRunner.RunEnumeration(); err != nil {
			b.Fatalf("RunEnumeration failed: %s", err)
		}
	}
}
