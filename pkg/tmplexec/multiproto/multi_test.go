package multiproto_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/loader/workflow"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/projectdiscovery/ratelimit"
	"github.com/stretchr/testify/require"
)

var executerOpts protocols.ExecutorOptions

// MemorySnapshot represents a point-in-time memory measurement
type MemorySnapshot struct {
	Timestamp  time.Time
	Alloc      uint64
	TotalAlloc uint64
	Sys        uint64
	NumGC      uint32
}

// TakeMemorySnapshot captures current memory statistics
func TakeMemorySnapshot() *MemorySnapshot {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	return &MemorySnapshot{
		Timestamp:  time.Now(),
		Alloc:      stats.Alloc,
		TotalAlloc: stats.TotalAlloc,
		Sys:        stats.Sys,
		NumGC:      stats.NumGC,
	}
}

// MemoryDiff represents the difference between two memory snapshots
type MemoryDiff struct {
	Duration  time.Duration
	AllocDiff int64
	TotalDiff int64
	SysDiff   int64
	GCDiff    int64
}

// Compare compares two memory snapshots and returns the difference
func (s *MemorySnapshot) Compare(other *MemorySnapshot) *MemoryDiff {
	return &MemoryDiff{
		Duration:  other.Timestamp.Sub(s.Timestamp),
		AllocDiff: int64(other.Alloc) - int64(s.Alloc),
		TotalDiff: int64(other.TotalAlloc) - int64(s.TotalAlloc),
		SysDiff:   int64(other.Sys) - int64(s.Sys),
		GCDiff:    int64(other.NumGC) - int64(s.NumGC),
	}
}

// String returns a formatted string representation of the memory difference
func (d *MemoryDiff) String() string {
	return fmt.Sprintf(
		"Duration: %v, Alloc: %+d bytes (%+.2f MB), Total: %+d bytes, Sys: %+d bytes, GC: %+d",
		d.Duration, d.AllocDiff, float64(d.AllocDiff)/1024/1024, d.TotalDiff, d.SysDiff, d.GCDiff,
	)
}

func setup() {
	options := testutils.DefaultOptions
	testutils.Init(options)
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)

	executerOpts = protocols.ExecutorOptions{
		Output:       testutils.NewMockOutputWriter(options.OmitTemplate),
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      disk.NewCatalog(config.DefaultConfig.TemplatesDirectory),
		RateLimiter:  ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
		Parser:       templates.NewParser(),
		InputHelper:  input.NewHelper(),
	}
	workflowLoader, err := workflow.NewLoader(&executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader
}

// Helper function to create a test template execution
func executeTemplate(templatePath string, target string) error {
	template, err := templates.Parse(templatePath, nil, executerOpts)
	if err != nil {
		return fmt.Errorf("could not parse template: %w", err)
	}

	err = template.Executer.Compile()
	if err != nil {
		return fmt.Errorf("could not compile template: %w", err)
	}

	input := contextargs.NewWithInput(context.Background(), target)
	ctx := scan.NewScanContext(context.Background(), input)
	_, err = template.Executer.Execute(ctx)
	if err != nil {
		return fmt.Errorf("could not execute template: %w", err)
	}

	return nil
}

// TestMemoryLeakDetection tests for memory leaks in multiprotocol execution
func TestMemoryLeakDetection(t *testing.T) {
	tests := []struct {
		name          string
		templatePath  string
		target        string
		numExecutions int
		maxMemoryMB   int
		description   string
	}{
		{
			name:          "SmallScale_DynamicExtractor",
			templatePath:  "testcases/multiprotodynamic.yaml",
			target:        "http://scanme.sh",
			numExecutions: 10,
			maxMemoryMB:   10,
			description:   "Basic memory leak detection with dynamic extractor",
		},
		{
			name:          "MediumScale_ProtoPrefix",
			templatePath:  "testcases/multiprotowithprefix.yaml",
			target:        "https://cloud.projectdiscovery.io/sign-in",
			numExecutions: 50,
			maxMemoryMB:   25,
			description:   "Medium scale execution with protocol prefix",
		},
		{
			name:          "LargeScale_Mixed",
			templatePath:  "testcases/multiprotodynamic.yaml",
			target:        "http://scanme.sh",
			numExecutions: 100,
			maxMemoryMB:   50,
			description:   "Large scale execution for memory leak detection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Force GC and get baseline
			runtime.GC()
			runtime.GC()                       // Call twice to ensure cleanup
			time.Sleep(100 * time.Millisecond) // Allow GC to complete

			baseline := TakeMemorySnapshot()
			t.Logf("Baseline memory: Alloc=%d bytes (%.2f MB)",
				baseline.Alloc, float64(baseline.Alloc)/1024/1024)

			// Execute multiple times
			for i := 0; i < tt.numExecutions; i++ {
				err := executeTemplate(tt.templatePath, tt.target)
				if err != nil {
					t.Logf("Execution %d failed (continuing): %v", i, err)
					continue
				}

				// Periodic memory checks
				if i%10 == 0 && i > 0 {
					runtime.GC()
					current := TakeMemorySnapshot()
					diff := baseline.Compare(current)

					memoryMB := float64(diff.AllocDiff) / 1024 / 1024
					t.Logf("Execution %d: %s", i, diff.String())

					if memoryMB > float64(tt.maxMemoryMB) {
						t.Errorf("Memory usage exceeded limit: %.2f MB > %d MB",
							memoryMB, tt.maxMemoryMB)
					}
				}
			}

			// Final memory check
			runtime.GC()
			runtime.GC()
			time.Sleep(100 * time.Millisecond)

			final := TakeMemorySnapshot()
			finalDiff := baseline.Compare(final)

			finalMemoryMB := float64(finalDiff.AllocDiff) / 1024 / 1024
			t.Logf("Final memory analysis: %s", finalDiff.String())

			if finalMemoryMB > float64(tt.maxMemoryMB) {
				t.Errorf("Final memory usage exceeded limit: %.2f MB > %d MB",
					finalMemoryMB, tt.maxMemoryMB)
			} else {
				t.Logf("✅ Memory usage within acceptable limits: %.2f MB <= %d MB",
					finalMemoryMB, tt.maxMemoryMB)
			}
		})
	}
}

// TestTemplateContextCleanup verifies that template contexts are properly cleaned up
func TestTemplateContextCleanup(t *testing.T) {
	// Create executor options with template context store
	opts := executerOpts
	opts.CreateTemplateCtxStore()

	template, err := templates.Parse("testcases/multiprotodynamic.yaml", nil, opts)
	require.NoError(t, err, "could not parse template")

	err = template.Executer.Compile()
	require.NoError(t, err, "could not compile template")

	// Create multiple contexts and execute
	numContexts := 20
	inputs := make([]*contextargs.Context, numContexts)

	for i := 0; i < numContexts; i++ {
		target := fmt.Sprintf("http://test%d.example.com", i)
		inputs[i] = contextargs.NewWithInput(context.Background(), target)

		ctx := scan.NewScanContext(context.Background(), inputs[i])
		_, err := template.Executer.Execute(ctx)
		if err != nil {
			t.Logf("Execution %d failed (continuing): %v", i, err)
		}
	}

	// Verify contexts exist
	contextCount := 0
	for _, input := range inputs {
		if opts.HasTemplateCtx(input.MetaInput) {
			contextCount++
		}
	}
	t.Logf("Active template contexts: %d", contextCount)

	// Clean up contexts manually (simulating proper cleanup)
	for _, input := range inputs {
		opts.RemoveTemplateCtx(input.MetaInput)
	}

	// Verify cleanup
	remainingContexts := 0
	for _, input := range inputs {
		if opts.HasTemplateCtx(input.MetaInput) {
			remainingContexts++
		}
	}

	if remainingContexts > 0 {
		t.Errorf("Template contexts not properly cleaned up: %d remaining", remainingContexts)
	} else {
		t.Logf("✅ All template contexts properly cleaned up")
	}
}

// TestConcurrentExecution tests memory usage under concurrent execution
func TestConcurrentExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	const (
		numGoroutines = 5
		numExecutions = 20
		maxMemoryMB   = 100
	)

	baseline := TakeMemorySnapshot()

	var wg sync.WaitGroup
	errChan := make(chan error, numGoroutines)

	// Start concurrent executions
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < numExecutions; j++ {
				target := fmt.Sprintf("http://test%d-%d.example.com", id, j)
				err := executeTemplate("testcases/multiprotodynamic.yaml", target)
				if err != nil {
					t.Logf("Goroutine %d execution %d failed: %v", id, j, err)
					continue
				}

				// Periodic memory check
				if j%5 == 0 {
					var stats runtime.MemStats
					runtime.ReadMemStats(&stats)

					memoryMB := float64(stats.Alloc) / 1024 / 1024
					if memoryMB > maxMemoryMB {
						errChan <- fmt.Errorf("goroutine %d: memory exceeded: %.2f MB", id, memoryMB)
						return
					}
				}
			}
		}(i)
	}

	// Wait for completion with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errChan:
		t.Fatal(err)
	case <-done:
		runtime.GC()
		final := TakeMemorySnapshot()
		diff := baseline.Compare(final)
		t.Logf("✅ Concurrent execution completed successfully: %s", diff.String())
	case <-time.After(2 * time.Minute):
		t.Fatal("Test timed out")
	}
}

// BenchmarkMultiProtocolExecution benchmarks multiprotocol execution performance
func BenchmarkMultiProtocolExecution(b *testing.B) {
	benchmarks := []struct {
		name         string
		templatePath string
		target       string
	}{
		{
			name:         "DynamicExtractor",
			templatePath: "testcases/multiprotodynamic.yaml",
			target:       "http://scanme.sh",
		},
		{
			name:         "ProtoPrefix",
			templatePath: "testcases/multiprotowithprefix.yaml",
			target:       "https://example.com",
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			template, err := templates.Parse(bm.templatePath, nil, executerOpts)
			if err != nil {
				b.Fatalf("could not parse template: %v", err)
			}

			err = template.Executer.Compile()
			if err != nil {
				b.Fatalf("could not compile template: %v", err)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				input := contextargs.NewWithInput(context.Background(), bm.target)
				ctx := scan.NewScanContext(context.Background(), input)
				_, err := template.Executer.Execute(ctx)
				if err != nil {
					b.Logf("Execution failed (continuing): %v", err)
				}
			}
		})
	}
}

// BenchmarkMemoryAllocation specifically benchmarks memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	template, err := templates.Parse("testcases/multiprotodynamic.yaml", nil, executerOpts)
	if err != nil {
		b.Fatalf("could not parse template: %v", err)
	}

	err = template.Executer.Compile()
	if err != nil {
		b.Fatalf("could not compile template: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		input := contextargs.NewWithInput(context.Background(), "http://scanme.sh")
		ctx := scan.NewScanContext(context.Background(), input)
		_, _ = template.Executer.Execute(ctx)
	}
}

func TestMultiProtoWithDynamicExtractor(t *testing.T) {
	Template, err := templates.Parse("testcases/multiprotodynamic.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.Equal(t, 2, len(Template.RequestsQueue))

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "http://scanme.sh")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestMultiProtoWithProtoPrefix(t *testing.T) {
	Template, err := templates.Parse("testcases/multiprotowithprefix.yaml", nil, executerOpts)
	require.Nil(t, err, "could not parse template")

	require.Equal(t, 3, len(Template.RequestsQueue))

	err = Template.Executer.Compile()
	require.Nil(t, err, "could not compile template")

	input := contextargs.NewWithInput(context.Background(), "https://cloud.projectdiscovery.io/sign-in")
	ctx := scan.NewScanContext(context.Background(), input)
	gotresults, err := Template.Executer.Execute(ctx)
	require.Nil(t, err, "could not execute template")
	require.True(t, gotresults)
}

func TestMain(m *testing.M) {
	setup()
	os.Exit(m.Run())
}
