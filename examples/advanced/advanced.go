package main

import (
	"context"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	syncutil "github.com/projectdiscovery/utils/sync"
)

func main() {
	ctx := context.Background()
	// when running nuclei in parallel for first time it is a good practice to make sure
	// templates exists first
	tm := installer.TemplateManager{}
	if err := tm.FreshInstallIfNotExists(); err != nil {
		panic(err)
	}

	// create nuclei engine with options
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx)
	if err != nil {
		panic(err)
	}
	// setup sizedWaitgroup to handle concurrency
	sg, err := syncutil.New(syncutil.WithSize(10))
	if err != nil {
		panic(err)
	}

	// scan 1 = run dns templates on scanme.sh
	sg.Add()
	go func() {
		defer sg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"},
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}),
			nuclei.WithHeaders([]string{"X-Bug-Bounty: pdteam"}),
			nuclei.EnablePassiveMode(),
		)
		if err != nil {
			panic(err)
		}
	}()

	// scan 2 = run templates with oast tags on honey.scanme.sh
	sg.Add()
	go func() {
		defer sg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"http://honey.scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}))
		if err != nil {
			panic(err)
		}
	}()

	// wait for all scans to finish
	sg.Wait()
	defer ne.Close()

	// Output:
	// [dns-saas-service-detection] scanme.sh
	// [nameserver-fingerprint] scanme.sh
	// [dns-saas-service-detection] honey.scanme.sh
}
