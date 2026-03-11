package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
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

// contentLengthVariance computes the sample variance of the given content-length
// values. Returns 0 if fewer than 2 values are provided.
func contentLengthVariance(lengths []int64) float64 {
	if len(lengths) < 2 {
		return 0
	}
	var sum float64
	for _, l := range lengths {
		sum += float64(l)
	}
	mean := sum / float64(len(lengths))
	var variance float64
	for _, l := range lengths {
		d := float64(l) - mean
		variance += d * d
	}
	return variance / float64(len(lengths)-1)
}

// Check sends canary requests to detect honeypot behavior.
// A honeypot returns 200 OK for completely random, non-existent paths.
//
// Detection requires BOTH conditions:
//  1. confidence (fraction of 200-status canary responses) >= threshold
//  2. Low body-length variance across responses — a real catch-all-200 app
//     typically returns varying page content; a honeypot returns nearly the
//     same page every time. If the standard deviation of observed content
//     lengths exceeds contentLenStdDevThreshold bytes we treat the host as a
//     real (non-honeypot) wildcard application and skip the honeypot flag.
//
// This avoids the false-positive where a legitimate site returns 200 with
// wildcard routing but serves meaningfully different content for each path.
const contentLenStdDevThreshold = 200.0 // bytes; tune as needed

func (h *HoneypotDetector) Check(ctx context.Context, target string) HoneypotResult {
	target = strings.TrimRight(target, "/")
	positives := 0
	var bodyLengths []int64

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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			positives++
			bodyLengths = append(bodyLengths, int64(len(body)))
		}
	}

	confidence := float64(positives) / float64(h.probes)

	// Require high confidence AND near-constant body length.
	// High variance implies different content per path → real wildcard app, not honeypot.
	stdDev := math.Sqrt(contentLengthVariance(bodyLengths))
	isHoneypot := confidence >= h.threshold && stdDev < contentLenStdDevThreshold

	reason := fmt.Sprintf("%d/%d canary requests returned 200 OK (body-length stddev=%.1f)", positives, h.probes, stdDev)

	if isHoneypot {
		gologger.Warning().Msgf("[honeypot] %s appears to be a honeypot (%.0f%% of canary requests returned 200, body stddev=%.1f)", target, confidence*100, stdDev)
	}

	return HoneypotResult{
		IsHoneypot: isHoneypot,
		Confidence: confidence,
		Reason:     reason,
	}
}
