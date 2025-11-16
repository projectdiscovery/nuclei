package main_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
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
	_ = os.Setenv("DISABLE_STDOUT", "true")

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
	_ = os.Unsetenv("DISABLE_STDOUT")

	os.Exit(exitCode)
}

// getUniqFilename generates a unique filename by appending .N if file exists
// Similar to wget's behavior: file.cpu.prof, file.cpu.1.prof, file.cpu.2.prof, etc.
func getUniqFilename(basePath string) string {
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		return basePath
	}

	lastDot := strings.LastIndex(basePath, ".")
	var name, ext string
	if lastDot != -1 {
		name = basePath[:lastDot]
		ext = basePath[lastDot:]
	} else {
		name = basePath
		ext = ""
	}

	for i := 1; ; i++ {
		newPath := fmt.Sprintf("%s.%d%s", name, i, ext)
		if _, err := os.Stat(newPath); os.IsNotExist(err) {
			return newPath
		}
	}
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
		ExecutionId: "test",
		Logger:      gologger.DefaultLogger,
	}
}

func runEnumBenchmark(b *testing.B, options *types.Options) {
	runner.ParseOptions(options)

	nucleiRunner, err := runner.New(options)
	if err != nil {
		b.Fatalf("failed to create runner: %s", err)
	}
	defer nucleiRunner.Close()

	benchNameSlug := strings.ReplaceAll(b.Name(), "/", "-")

	// Start CPU profiling
	cpuProfileBase := fmt.Sprintf("%s.cpu.prof", benchNameSlug)
	cpuProfilePath := getUniqFilename(cpuProfileBase)
	cpuProfile, err := os.Create(cpuProfilePath)
	if err != nil {
		b.Fatalf("failed to create CPU profile: %s", err)
	}
	defer func() { _ = cpuProfile.Close() }()

	if err := pprof.StartCPUProfile(cpuProfile); err != nil {
		b.Fatalf("failed to start CPU profile: %s", err)
	}
	defer pprof.StopCPUProfile()

	b.ReportAllocs()

	for b.Loop() {
		if err := nucleiRunner.RunEnumeration(); err != nil {
			b.Fatalf("%s failed: %s", b.Name(), err)
		}
	}

	b.StopTimer()

	// Write heap profile
	heapProfileBase := fmt.Sprintf("%s.heap.prof", benchNameSlug)
	heapProfilePath := getUniqFilename(heapProfileBase)
	heapProfile, err := os.Create(heapProfilePath)
	if err != nil {
		b.Fatalf("failed to create heap profile: %s", err)
	}
	defer func() { _ = heapProfile.Close() }()

	runtime.GC() // Force GC before heap profile
	if err := pprof.WriteHeapProfile(heapProfile); err != nil {
		b.Fatalf("failed to write heap profile: %s", err)
	}
}

func BenchmarkRunEnumeration(b *testing.B) {
	// Default case: run enumeration with default options == all nuclei-templates
	b.Run("Default", func(b *testing.B) {
		options := getDefaultOptions()
		options.Targets = []string{targetURL}

		runEnumBenchmark(b, options)
	})

	// Case: https://github.com/projectdiscovery/nuclei/pull/6258
	b.Run("Multiproto", func(b *testing.B) {
		options := getDefaultOptions()
		options.Targets = []string{targetURL}
		options.Templates = []string{"./cmd/nuclei/testdata/benchmark/multiproto/"}

		runEnumBenchmark(b, options)
	})
}
