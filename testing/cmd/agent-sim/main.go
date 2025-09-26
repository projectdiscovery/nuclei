package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

func memMB() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc / (1024 * 1024)
}

func snapshotCaches(label string, engines []*nuclei.NucleiEngine) {
	fmt.Println(label)
	max := 3
	if len(engines) < max {
		max = len(engines)
	}
	var base *templates.Parser
	for i := 0; i < max; i++ {
		p := engines[i].GetParser()
		if base == nil {
			base = p
		}
		fmt.Printf("  engine[%d]: parsed_cache_ptr=%p compiled_cache_ptr=%p parsed_count=%d compiled_count=%d\n", i, p.Cache(), p.CompiledCache(), p.ParsedCount(), p.CompiledCount())
	}
	equalParsed := true
	equalCompiled := true
	for i := 1; i < len(engines); i++ {
		if engines[i].GetParser().Cache() != base.Cache() {
			equalParsed = false
		}
		if engines[i].GetParser().CompiledCache() != base.CompiledCache() {
			equalCompiled = false
		}
	}
	fmt.Println("  parsed cache shared across engines:", equalParsed)
	fmt.Println("  compiled cache shared across engines:", equalCompiled)
}

func runEngines(chunks int, targets []string, execute bool) (time.Duration, error) {
	start := time.Now()
	engines := make([]*nuclei.NucleiEngine, 0, chunks)
	for i := 0; i < chunks; i++ {
		ne, err := nuclei.NewNucleiEngineCtx(context.Background())
		if err != nil {
			return 0, fmt.Errorf("engine create: %w", err)
		}
		engines = append(engines, ne)
	}

	// Load templates
	for _, ne := range engines {
		if err := ne.LoadAllTemplates(); err != nil {
			return 0, fmt.Errorf("load templates: %w", err)
		}
	}

	if execute {
		// Execute scans concurrently with a global 60s timeout to prevent long runs
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		for _, ne := range engines {
			ne := ne
			ne.LoadTargets(targets, false)
			wg.Add(1)
			go func() {
				defer wg.Done()
				// ignore callback output
				_ = ne.ExecuteCallbackWithCtx(ctx)
			}()
		}
		wg.Wait()
	}

	for _, ne := range engines {
		ne.Close()
	}
	return time.Since(start), nil
}

func main() {
	var chunks int
	var targetsCSV string
	var execute bool
	flag.IntVar(&chunks, "chunks", 10, "number of simulated chunk engines")
	flag.StringVar(&targetsCSV, "targets", "https://scanme.sh,https://honey.scanme.sh", "comma-separated targets")
	flag.BoolVar(&execute, "execute", false, "execute scans after loading templates (default: false)")
	flag.Parse()

	// Ensure templates directory exists
	templatesDir := config.DefaultConfig.TemplatesDirectory
	if fi, err := os.Stat(templatesDir); err != nil || !fi.IsDir() {
		fmt.Printf("templates directory not found: %s\n", templatesDir)
		os.Exit(1)
	}

	targets := []string{}
	for _, t := range strings.Split(targetsCSV, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			targets = append(targets, t)
		}
	}

	fmt.Println("=== Agent-sim: without shared caches ===")
	_ = os.Unsetenv("NUCLEI_USE_SHARED_COMPILED")
	runtime.GC()
	before := memMB()
	// create engines to snapshot cache sharing behavior
	enginesNS := make([]*nuclei.NucleiEngine, 0, chunks)
	for i := 0; i < chunks; i++ {
		ne, err := nuclei.NewNucleiEngineCtx(context.Background())
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		enginesNS = append(enginesNS, ne)
	}
	for _, ne := range enginesNS {
		if err := ne.LoadAllTemplates(); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
	}
	snapshotCaches("cache state (no_shared):", enginesNS)
	for _, ne := range enginesNS {
		ne.Close()
	}
	durNoShared, err := runEngines(chunks, targets, execute)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	runtime.GC()
	after := memMB()
	fmt.Printf("no_shared: duration=%s heap_before=%dMB heap_after=%dMB\n", durNoShared, before, after)

	fmt.Println("\n=== Agent-sim: with shared compiled cache ===")
	_ = os.Setenv("NUCLEI_USE_SHARED_COMPILED", "1")
	runtime.GC()
	before = memMB()
	enginesSC := make([]*nuclei.NucleiEngine, 0, chunks)
	for i := 0; i < chunks; i++ {
		ne, err := nuclei.NewNucleiEngineCtx(context.Background())
		if err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		enginesSC = append(enginesSC, ne)
	}
	for _, ne := range enginesSC {
		if err := ne.LoadAllTemplates(); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
	}
	snapshotCaches("cache state (shared-compiled):", enginesSC)
	for _, ne := range enginesSC {
		ne.Close()
	}
	durSharedCompiled, err := runEngines(chunks, targets, execute)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	runtime.GC()
	after = memMB()
	fmt.Printf("shared_compiled: duration=%s heap_before=%dMB heap_after=%dMB\n", durSharedCompiled, before, after)

	fmt.Println("\nDone.")
}
