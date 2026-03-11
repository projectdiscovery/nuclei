package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// HoneypotDetector identifies hosts that respond positively to all requests,
// indicating they are honeypots designed to fool vulnerability scanners.
type HoneypotDetector struct {
	client    *http.Client
	threshold float64
	probes    int
}

// HoneypotResult contains honeypot detection results.
type HoneypotResult struct {
	IsHoneypot bool
	Confidence float64 // 0.0-1.0
	Reason     string
}

// NewHoneypotDetector creates a new honeypot detector.
func NewHoneypotDetector(timeout time.Duration, threshold float64, probes int) *HoneypotDetector {
	if threshold <= 0 {
		threshold = 0.8
	}
	if probes <= 0 {
		probes = 3
	}
	return &HoneypotDetector{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		threshold: threshold,
		probes:    probes,
	}
}

// randomHex generates a random hex string of n bytes.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Check sends canary requests to detect honeypot behavior.
// A honeypot returns 200 OK for completely random, non-existent paths.
func (h *HoneypotDetector) Check(ctx context.Context, target string) HoneypotResult {
	target = strings.TrimRight(target, "/")
	positives := 0

	for i := 0; i < h.probes; i++ {
		path := fmt.Sprintf("/nuclei-canary-%s-%s", randomHex(4), randomHex(4))
		url := target + path

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; nuclei)")

		resp, err := h.client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()

		// A real server returns 404 for random paths; a honeypot returns 200
		if resp.StatusCode == http.StatusOK {
			positives++
		}
	}

	confidence := float64(positives) / float64(h.probes)
	isHoneypot := confidence >= h.threshold

	if isHoneypot {
		gologger.Warning().Msgf("[honeypot] %s appears to be a honeypot (%.0f%% of canary requests returned 200)", target, confidence*100)
	}

	return HoneypotResult{
		IsHoneypot: isHoneypot,
		Confidence: confidence,
		Reason:     fmt.Sprintf("%d/%d canary requests returned 200 OK", positives, h.probes),
	}
}
