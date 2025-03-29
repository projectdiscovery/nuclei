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

	// Create a buffered channel to synchronize the state changes (with capacity 1)
	stateUpdateChan := make(chan bool, 1)

	go testRateLimit(&wg, ne, stateUpdateChan)
	go testThreadsAndBulkSize(&wg, ne, stateUpdateChan)
	go testPayloadConcurrency(&wg, ne, stateUpdateChan)

	// Wait for all tasks to finish
	wg.Wait()

	// Execute the callback after all tests
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}
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

func testRateLimit(wg *sync.WaitGroup, ne *nuclei.NucleiEngine, stateUpdateChan chan bool) {
	defer wg.Done()
	verifyRateLimit(ne, 1, 5000, stateUpdateChan)
}

func testThreadsAndBulkSize(wg *sync.WaitGroup, ne *nuclei.NucleiEngine, stateUpdateChan chan bool) {
	defer wg.Done()
	initialTemplateThreads, initialBulkSize := 1, 1
	verifyThreadsAndBulkSize(ne, initialTemplateThreads, initialBulkSize, 25, 25, stateUpdateChan)
}

func testPayloadConcurrency(wg *sync.WaitGroup, ne *nuclei.NucleiEngine, stateUpdateChan chan bool) {
	defer wg.Done()
	verifyPayloadConcurrency(ne, 1, 500, stateUpdateChan)
}

func verifyRateLimit(ne *nuclei.NucleiEngine, initialRate, finalRate int, stateUpdateChan chan bool) {
	if ne.GetExecuterOptions().RateLimiter.GetLimit() != uint(initialRate) {
		panic("wrong initial rate limit")
	}

	// Send a signal to update the state after the first check
	stateUpdateChan <- true

	// Wait until the update is processed
	<-stateUpdateChan

	ne.Options().RateLimit = finalRate

	// Notify that the state update is complete
	stateUpdateChan <- true

	// Wait until the update is processed
	<-stateUpdateChan

	if ne.GetExecuterOptions().RateLimiter.GetLimit() != uint(finalRate) {
		panic("wrong final rate limit")
	}
}

func verifyThreadsAndBulkSize(ne *nuclei.NucleiEngine, initialThreads, initialBulk, finalThreads, finalBulk int, stateUpdateChan chan bool) {
	if ne.Options().TemplateThreads != initialThreads || ne.Options().BulkSize != initialBulk {
		panic("wrong initial standard concurrency")
	}

	// Send a signal to update the state after the first check
	stateUpdateChan <- true

	// Wait until the update is processed
	<-stateUpdateChan

	ne.Options().TemplateThreads = finalThreads
	ne.Options().BulkSize = finalBulk

	// Notify that the state update is complete
	stateUpdateChan <- true

	// Wait until the update is processed
	<-stateUpdateChan

	if ne.Engine().GetWorkPool().InputPool(types.HTTPProtocol).Size != finalBulk || ne.Engine().WorkPool().Default.Size != finalThreads {
		log.Fatal("wrong final concurrency", ne.Engine().WorkPool().Default.Size, finalThreads, ne.Engine().GetWorkPool().InputPool(types.HTTPProtocol).Size, finalBulk)
	}
}

func verifyPayloadConcurrency(ne *nuclei.NucleiEngine, initialPayloadConcurrency, finalPayloadConcurrency int, stateUpdateChan chan bool) {
	if ne.Options().PayloadConcurrency != initialPayloadConcurrency {
		panic("wrong initial payload concurrency")
	}

	// Send a signal to update the state after the first check
	stateUpdateChan <- true

	// Wait until the update is processed
	<-stateUpdateChan

	ne.Options().PayloadConcurrency = finalPayloadConcurrency

	// Notify that the state update is complete
	stateUpdateChan <- true

	// Wait until the update is processed
	<-stateUpdateChan

	if ne.GetExecuterOptions().GetThreadsForNPayloadRequests(100, 0) != finalPayloadConcurrency {
		panic("wrong final payload concurrency")
	}
}
