package main

import (
	"log"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

func main() {
	ne, err := initializeNucleiEngine()
	if err != nil {
		panic(err)
	}
	defer ne.Close()

	ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)

	var wg sync.WaitGroup
	wg.Add(3)

	go testRateLimit(&wg, ne)
	go testThreadsAndBulkSize(&wg, ne)
	go testPayloadConcurrency(&wg, ne)

	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}

	wg.Wait()
}

func initializeNucleiEngine() (*nuclei.NucleiEngine, error) {
	return nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}),
		nuclei.WithGlobalRateLimit(1, time.Second),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           1,
			HostConcurrency:               1,
			HeadlessHostConcurrency:       1,
			HeadlessTemplateConcurrency:   1,
			JavascriptTemplateConcurrency: 1,
			TemplatePayloadConcurrency:    1,
			ProbeConcurrency:              1,
		}),
	)
}

func testRateLimit(wg *sync.WaitGroup, ne *nuclei.NucleiEngine) {
	defer wg.Done()
	verifyRateLimit(ne, 1, 5000)
}

func testThreadsAndBulkSize(wg *sync.WaitGroup, ne *nuclei.NucleiEngine) {
	defer wg.Done()
	initialTemplateThreads, initialBulkSize := 1, 1
	verifyThreadsAndBulkSize(ne, initialTemplateThreads, initialBulkSize, 25, 25)
}

func testPayloadConcurrency(wg *sync.WaitGroup, ne *nuclei.NucleiEngine) {
	defer wg.Done()
	verifyPayloadConcurrency(ne, 1, 500)
}

func verifyRateLimit(ne *nuclei.NucleiEngine, initialRate, finalRate int) {
	if ne.GetExecuterOptions().RateLimiter.GetLimit() != uint(initialRate) {
		panic("wrong initial rate limit")
	}
	time.Sleep(5 * time.Second)
	ne.Options().RateLimit = finalRate
	time.Sleep(20 * time.Second)
	if ne.GetExecuterOptions().RateLimiter.GetLimit() != uint(finalRate) {
		panic("wrong final rate limit")
	}
}

func verifyThreadsAndBulkSize(ne *nuclei.NucleiEngine, initialThreads, initialBulk, finalThreads, finalBulk int) {
	if ne.Options().TemplateThreads != initialThreads || ne.Options().BulkSize != initialBulk {
		panic("wrong initial standard concurrency")
	}
	time.Sleep(5 * time.Second)
	ne.Options().TemplateThreads = finalThreads
	ne.Options().BulkSize = finalBulk
	time.Sleep(20 * time.Second)
	if ne.Engine().GetWorkPool().InputPool(types.HTTPProtocol).Size != finalBulk || ne.Engine().WorkPool().Default.Size != finalThreads {
		log.Fatal("wrong final concurrency", ne.Engine().WorkPool().Default.Size, finalThreads, ne.Engine().GetWorkPool().InputPool(types.HTTPProtocol).Size, finalBulk)
	}
}

func verifyPayloadConcurrency(ne *nuclei.NucleiEngine, initialPayloadConcurrency, finalPayloadConcurrency int) {
	if ne.Options().PayloadConcurrency != initialPayloadConcurrency {
		panic("wrong initial payload concurrency")
	}
	time.Sleep(5 * time.Second)
	ne.Options().PayloadConcurrency = finalPayloadConcurrency
	time.Sleep(20 * time.Second)
	if ne.GetExecuterOptions().GetThreadsForNPayloadRequests(100, 0) != finalPayloadConcurrency {
		panic("wrong final payload concurrency")
	}
}
