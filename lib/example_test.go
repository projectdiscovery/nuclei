//go:build !race
// +build !race

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

func TestMain(m *testing.M) {
	// this file only contains testtables examples https://go.dev/blog/examples
	// and actual functionality test are in sdk_test.go
	if ci.IsCI() {
		// no need to run this test on github actions
		return
	}

	os.Exit(m.Run())
}
