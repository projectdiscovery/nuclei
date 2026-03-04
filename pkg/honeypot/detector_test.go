package honeypot

import (
	"sync"
	"testing"
)

func TestDetector_BelowThreshold(t *testing.T) {
	d := NewDetector(3)
	host := "example.com"
	// record two unique matches
	if flagged := d.RecordMatch(host, "tpl1"); flagged {
		t.Fatal("host should not be flagged after 1 match")
	}
	if flagged := d.RecordMatch(host, "tpl2"); flagged {
		t.Fatal("host should not be flagged after 2 matches")
	}
	if d.IsFlagged(host) {
		t.Fatal("host should not be flagged yet")
	}
}

func TestDetector_AtThreshold(t *testing.T) {
	d := NewDetector(2)
	host := "example.com"
	// first match does not exceed
	if d.RecordMatch(host, "tplA") {
		t.Fatal("should not flag at first match")
	}
	// second unique match reaches threshold
	if !d.RecordMatch(host, "tplB") {
		t.Fatal("should flag at second match")
	}
	if !d.IsFlagged(host) {
		t.Fatal("host should remain flagged after threshold exceeded")
	}
}

func TestDetector_Concurrent(t *testing.T) {
	threshold := 5
	d := NewDetector(threshold)
	host := "concurrent.example"
	var wg sync.WaitGroup
	// spawn goroutines recording distinct template IDs
	for i := 0; i < threshold; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tplID := "tpl" + string('A'+id)
			d.RecordMatch(host, tplID)
		}(i)
	}
	wg.Wait()
	if !d.IsFlagged(host) {
		t.Fatal("host should be flagged after concurrent matches reach threshold")
	}
}