package sdk_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/utils/env"
	"github.com/stretchr/testify/require"
	"github.com/tarunKoyalwar/goleak"
)

var knownLeaks = []goleak.Option{
	// prettyify the output and generate dependency graph and more details instead of just stack output
	goleak.Pretty(),
	// net/http transport maintains idle connections which are closed with cooldown
	// hence they don't count as leaks
	goleak.IgnoreAnyFunction("net/http.(*http2ClientConn).readLoop"),
}

func TestSimpleNuclei(t *testing.T) {
	fn := func() {
		defer func() {
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		ne, err := nuclei.NewNucleiEngineCtx(
			context.TODO(),
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}), // filter dns templates
			nuclei.EnableStatsWithOpts(nuclei.StatsOptions{JSON: true}),
		)
		require.Nil(t, err)
		ne.LoadTargets([]string{"scanme.sh"}, false) // probe non http/https target is set to false here
		// when callback is nil it nuclei will print JSON output to stdout
		err = ne.ExecuteWithCallback(nil)
		require.Nil(t, err)
		defer ne.Close()
	}

	// this is shared test so needs to be run as seperate process
	if env.GetEnvOrDefault("TestSimpleNuclei", false) {
		// run as new process
		cmd := exec.Command(os.Args[0], "-test.run=TestSimpleNuclei")
		cmd.Env = append(os.Environ(), "TestSimpleNuclei=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}

func TestSimpleNucleiRemote(t *testing.T) {
	fn := func() {
		defer func() {
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		ne, err := nuclei.NewNucleiEngineCtx(
			context.TODO(),
			nuclei.WithTemplatesOrWorkflows(
				nuclei.TemplateSources{
					RemoteTemplates: []string{"https://cloud.projectdiscovery.io/public/nameserver-fingerprint.yaml"},
				},
			),
		)
		require.Nil(t, err)
		ne.LoadTargets([]string{"scanme.sh"}, false) // probe non http/https target is set to false here
		err = ne.LoadAllTemplates()
		require.Nil(t, err, "could not load templates")
		// when callback is nil it nuclei will print JSON output to stdout
		err = ne.ExecuteWithCallback(nil)
		require.Nil(t, err)
		defer ne.Close()
	}
	// this is shared test so needs to be run as seperate process
	if env.GetEnvOrDefault("TestSimpleNucleiRemote", false) {
		cmd := exec.Command(os.Args[0], "-test.run=TestSimpleNucleiRemote")
		cmd.Env = append(os.Environ(), "TestSimpleNucleiRemote=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}

func TestThreadSafeNuclei(t *testing.T) {
	fn := func() {
		defer func() {
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		// create nuclei engine with options
		ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.TODO())
		require.Nil(t, err)

		// scan 1 = run dns templates on scanme.sh
		t.Run("scanme.sh", func(t *testing.T) {
			err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}))
			require.Nil(t, err)
		})

		// scan 2 = run dns templates on honey.scanme.sh
		t.Run("honey.scanme.sh", func(t *testing.T) {
			err = ne.ExecuteNucleiWithOpts([]string{"honey.scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}))
			require.Nil(t, err)
		})

		// wait for all scans to finish
		defer ne.Close()
	}

	if env.GetEnvOrDefault("TestThreadSafeNuclei", false) {
		cmd := exec.Command(os.Args[0], "-test.run=TestThreadSafeNuclei")
		cmd.Env = append(os.Environ(), "TestThreadSafeNuclei=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}

func TestWithVarsNuclei(t *testing.T) {
	fn := func() {
		defer func() {
			// resources like leveldb have a delay to commit in-memory resources
			// to disk, typically 1-2 seconds, so we wait for 2 seconds
			time.Sleep(2 * time.Second)
			goleak.VerifyNone(t, knownLeaks...)
		}()
		ne, err := nuclei.NewNucleiEngineCtx(
			context.TODO(),
			nuclei.EnableSelfContainedTemplates(),
			nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{"http/token-spray/api-1forge.yaml"}}),
			nuclei.WithVars([]string{"token=foobar"}),
			nuclei.WithVerbosity(nuclei.VerbosityOptions{Debug: true}),
		)
		require.Nil(t, err)
		ne.LoadTargets([]string{"scanme.sh"}, true) // probe http/https target is set to true here
		err = ne.ExecuteWithCallback(nil)
		require.Nil(t, err)
		defer ne.Close()
	}
	// this is shared test so needs to be run as seperate process
	if env.GetEnvOrDefault("TestWithVarsNuclei", false) {
		cmd := exec.Command(os.Args[0], "-test.run=TestWithVarsNuclei")
		cmd.Env = append(os.Environ(), "TestWithVarsNuclei=true")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("process ran with error %s, output: %s", err, out)
		}
	} else {
		fn()
	}
}
