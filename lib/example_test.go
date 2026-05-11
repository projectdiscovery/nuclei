//go:build !race

package nuclei_test

import (
	"os"
	"testing"

	"github.com/kitabisa/go-ci"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/remeh/sizedwaitgroup"
)

// A very simple example on how to use nuclei engine
func ExampleNucleiEngine() {
	// create nuclei engine with options
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"self-signed-ssl"}}), // only run self-signed-ssl template
	)
	if err != nil {
		panic(err)
	}
	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"scanme.sh"}, false)
	// when callback is nil it nuclei will print JSON output to stdout
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}
	defer ne.Close()

	// Output:
	// [self-signed-ssl] scanme.sh:443
}

func ExampleThreadSafeNucleiEngine() {
	// create nuclei engine with options
	ne, err := nuclei.NewThreadSafeNucleiEngine()
	if err != nil {
		panic(err)
	}
	// setup sizedWaitgroup to handle concurrency
	// here we are using sizedWaitgroup to limit concurrency to 1
	// but can be anything in general
	sg := sizedwaitgroup.New(1)

	// scan 1 = run dns templates on scanme.sh
	sg.Add()
	go func() {
		defer sg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"},
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"nameserver-fingerprint"}}), // only run self-signed-ssl template
		)
		if err != nil {
			panic(err)
		}
	}()

	// scan 2 = run dns templates on honey.scanme.sh
	sg.Add()
	go func() {
		defer sg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"honey.scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}))
		if err != nil {
			panic(err)
		}
	}()

	// wait for all scans to finish
	sg.Wait()
	defer ne.Close()

	// Output:
	// [nameserver-fingerprint] scanme.sh
	// [caa-fingerprint] honey.scanme.sh
}

// ExampleWithPDCPUpload shows how to upload findings to the PDCP dashboard
// from an SDK-driven scan, matching the CLI's -dashboard / -scan-id / -team-id
// flags. Credentials come from PDCP_API_KEY or
// ~/.config/nuclei/.pdcp/credentials.yaml; if they are missing the engine
// continues without uploading.
//
// Pass an existing scanID to append to that scan; pass an empty string to let
// the server create a new scan on first upload.
func ExampleWithPDCPUpload() {
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"self-signed-ssl"}}),
		nuclei.WithPDCPUpload("" /* scanID */, "" /* teamID, "" = personal */),
	)
	if err != nil {
		panic(err)
	}
	defer ne.Close()
	ne.LoadTargets([]string{"scanme.sh"}, false)
	if err := ne.ExecuteWithCallback(nil); err != nil {
		panic(err)
	}
}

// ExampleWithConfigFile shows how to ingest a CLI-style `-config` YAML file
// from SDK code, which is useful when a control plane (or pd-agent) wants to
// hand the engine the same configuration shape the CLI accepts.
//
// WithConfigFile only writes fields the YAML explicitly sets — other fields
// retain the engine's default values or any value set by With* options
// earlier in the chain. To override a YAML-set value, apply the With* option
// AFTER WithConfigFile.
func ExampleWithConfigFile() {
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithConfigFile("nuclei.yaml"),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{IDs: []string{"self-signed-ssl"}}),
	)
	if err != nil {
		panic(err)
	}
	defer ne.Close()
	ne.LoadTargets([]string{"scanme.sh"}, false)
	if err := ne.ExecuteWithCallback(nil); err != nil {
		panic(err)
	}
}

func TestMain(m *testing.M) {
	// this file only contains testtables examples https://go.dev/blog/examples
	// and actual functionality test are in sdk_test.go
	if ci.IsCI() {
		// no need to run this test on github actions
		return
	}

	os.Exit(m.Run())
}
