package main

import (
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	syncutil "github.com/projectdiscovery/utils/sync"
)

func main() {
	// create nuclei engine with options
	ne, err := nuclei.NewThreadSafeNucleiEngine()
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
