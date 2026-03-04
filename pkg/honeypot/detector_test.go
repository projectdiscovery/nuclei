package honeypot

import (
	"sync"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"example.com":              "example.com",
		"EXAMPLE.COM:8080":        "example.com",
		"http://user:pass@ExAmPlE.com": "example.com",
		"[2001:db8::1]:443":       "2001:db8::1",
		"https://[FE80::2]" :      "fe80::2",
	}
	for raw, want := range cases {
		if got := NormalizeHost(raw); got != want {
			t.Errorf("NormalizeHost(%q) = %q; want %q", raw, got, want)
		}
	}
}

func TestDetectorThreshold(t *testing.T) {
	d := NewDetector(3)
	host := "http://Example.com"
	if d.IsFlagged(host) {
		t.Error("IsFlagged should be false before matches")
	}
	// record distinct template IDs
	if d.RecordMatch(host, "t1") {
		t.Error("should not flag at 1")
	}
	if d.RecordMatch(host, "t1") {
		t.Error("duplicate template should not count twice")
	}
	if d.RecordMatch(host, "t2") {
		t.Error("should not flag at 2")
	}
	// third unique
	if !d.RecordMatch(host, "t3") {
		t.Error("should flag at 3")
	}
	if !d.IsFlagged(host) {
		t.Error("IsFlagged should be true after threshold crossed")
	}
}

func TestDetectorConcurrent(t *testing.T) {
	d := NewDetector(100)
	host := "concurrent.test"
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tmpl := "id" + string(i)
			d.RecordMatch(host, tmpl)
		}(i)
	}
	wg.Wait()
	if !d.IsFlagged(host) {
		t.Error("should flag after 100 concurrent unique matches")
	}
}

func TestNilDetector(t *testing.T) {
	var d *Detector
	if d.RecordMatch("a", "b") {
		t.Error("nil Detector should not panic and return false")
	}
	if d.IsFlagged("a") {
		t.Error("nil Detector IsFlagged should return false")
	}
}