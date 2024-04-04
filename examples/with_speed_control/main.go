package main

import (
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

func main() {
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			IDs:         []string{"header-command-injection"},
			IncludeTags: []string{"fuzz"},
		}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}),
		nuclei.WithGlobalRateLimit(1, time.Second),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           1,
			HostConcurrency:               1,
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: 1,
			TemplatePayloadConcurrency:    1,
		}),
	)
	if err != nil {
		panic(err)
	}
	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)

	var wgtest sync.WaitGroup

	// speed tests
	// increase rate limit
	wgtest.Add(1)
	go func() {
		defer wgtest.Done()
		initialRate := ne.GetExecuterOptions().RateLimiter.GetLimit()
		if initialRate != 1 {
			panic("wrong initial rate limit")
		}
		time.Sleep(10 * time.Second)
		ne.Options().RateLimit = 5
		time.Sleep(10 * time.Second)
		finalRate := ne.GetExecuterOptions().RateLimiter.GetLimit()
		if finalRate != 5 {
			panic("wrong final rate limit")
		}
	}()

	// increase threads and bulk size
	wgtest.Add(1)
	go func() {
		defer wgtest.Done()
		initialTemplateThreads := ne.Options().TemplateThreads
		initialBulkSize := ne.Options().BulkSize
		if initialTemplateThreads != 1 || initialBulkSize != 1 {
			panic("wrong initial standard concurrency")
		}
		time.Sleep(10 * time.Second)
		ne.Options().TemplateThreads = 5
		ne.Options().BulkSize = 25
		time.Sleep(10 * time.Second)
		// check new values via workpool
		finalTemplateThreads := ne.Engine().WorkPool().Default.Size
		finalBulkSize := ne.Engine().GetWorkPool().InputPool(types.HTTPProtocol).Size
		if finalTemplateThreads != 5 && finalBulkSize != 25 {
			panic("wrong final concurreny")
		}
	}()

	// increase payload concurrency
	wgtest.Add(1)
	go func() {
		defer wgtest.Done()
		initialpayloadConcurrency := ne.Options().PayloadConcurrency
		if initialpayloadConcurrency != 1 {
			panic("wrong initial payload concurrency")
		}
		time.Sleep(10 * time.Second)
		ne.Options().PayloadConcurrency = 5
		time.Sleep(10 * time.Second)

		// the ongoing and next payload iterations will retrieve parallelism from this function
		// it should have the new set value, that will be cascade applied to all running adaptive wait groups
		finalPayloadConcurrency := ne.GetExecuterOptions().GetThreadsForNPayloadRequests(100, 0)
		if finalPayloadConcurrency != 5 {
			panic("wrong initial payload concurrency")
		}
	}()

	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}
	defer ne.Close()

	wgtest.Wait()
}
