package nuclei_test

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/stretchr/testify/require"
)

func TestContextCancelNucleiEngine(t *testing.T) {
	// create nuclei engine with options
	ctx, cancel := context.WithCancel(context.Background())
	ne, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 0}),
	)
	require.NoError(t, err, "could not create nuclei engine")

	go func() {
		time.Sleep(time.Second * 2)
		cancel()
		log.Println("Test: context cancelled")
	}()

	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)
	// when callback is nil it nuclei will print JSON output to stdout
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		// we expect a context cancellation error
		require.ErrorIs(t, err, context.Canceled, "was expecting context cancellation error")
	}
	defer ne.Close()
}

func TestSharedParserOptIn(t *testing.T) {
	os.Setenv("NUCLEI_USE_SHARED_PARSER", "1")
	t.Cleanup(func() { os.Unsetenv("NUCLEI_USE_SHARED_PARSER") })

	ne, err := nuclei.NewNucleiEngineCtx(context.Background())
	if err != nil {
		t.Fatalf("engine error: %v", err)
	}
	p := ne.GetParser()
	if p == nil {
		t.Fatalf("expected templates.Parser")
	}
	ne2, err := nuclei.NewNucleiEngineCtx(context.Background())
	if err != nil {
		t.Fatalf("engine2 error: %v", err)
	}
	p2 := ne2.GetParser()
	if p2 == nil {
		t.Fatalf("expected templates.Parser2")
	}
	if p.Cache() != p2.Cache() {
		t.Fatalf("expected shared parsed cache across engines when opt-in is set")
	}
}
