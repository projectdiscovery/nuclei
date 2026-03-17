package main

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var honeypotTestCases = []TestCaseInfo{
	{Path: "protocols/http/honeypot-instant.yaml", TestCase: &honeypotInstant{}},
	{Path: "protocols/http/honeypot-simulated.yaml", TestCase: &honeypotSimulated{}},
	{Path: "protocols/http/honeypot-stateless.yaml", TestCase: &honeypotStateless{}},
	{Path: "protocols/http/honeypot-real.yaml", TestCase: &honeypotReal{}},
}

// --- Test Case A: Instant Honeypot ---
// Mock server returns 200 OK immediately (<1ms) with zero variance.
// Expected: Nuclei flags timing_coefficient_of_variation < 0.05.
type honeypotInstant struct{}

func (h *honeypotInstant) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Instant response to simulate low-interaction honeypot
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// --- Test Case B: Simulated Honeypot ---
// Mock server sleeps exactly 100ms for every request.
// Expected: Nuclei flags timing_std_dev == 0 or CV == 0.
type honeypotSimulated struct{}

func (h *honeypotSimulated) Execute(filePath string) error {
	router := httprouter.New()
	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Fixed delay to simulate artificial latency
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// --- Test Case C: Stateless Honeypot ---
// Mock server accepts POST /create (latency varies), but GET /check returns 404.
// Expected: Nuclei flags "Stateless" via the validation matcher.
type honeypotStateless struct{}

func (h *honeypotStateless) Execute(filePath string) error {
	router := httprouter.New()

	// Endpoint to be timed
	router.POST("/create", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Random latency to confuse simple timing checks
		delay := time.Duration(rand.Intn(150)+50) * time.Millisecond
		time.Sleep(delay)
		w.WriteHeader(http.StatusOK)
	})

	// Validation endpoint that fails to find state
	router.GET("/check", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Honeypot behavior: Claims success but state doesn't persist
		w.WriteHeader(http.StatusNotFound)
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// --- Test Case D: Real Server ---
// Mock server sleeps random duration (50ms−200ms) and persists state.
// Expected: Nuclei reports negative (no match).
type honeypotReal struct{}

func (h *honeypotReal) Execute(filePath string) error {
	router := httprouter.New()

	// Thread-safe map to simulate state persistence
	var mu sync.Mutex
	store := make(map[string]bool)

	// Endpoint to be timed
	router.POST("/create", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Random latency typical of real processing
		delay := time.Duration(rand.Intn(150)+50) * time.Millisecond
		time.Sleep(delay)

		mu.Lock()
		store["data"] = true
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	})

	// Validation endpoint verifies state
	router.GET("/check", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		mu.Lock()
		_, exists := store["data"]
		mu.Unlock()

		if exists {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Data found")
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	ts := httptest.NewServer(router)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	// Expected: 0 results (Negative test) because variance is high AND state persists.
	return expectResultsCount(results, 0)
}
