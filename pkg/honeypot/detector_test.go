package honeypot

import (
	"fmt"
	"sync"
	"testing"
)

func TestDetector_FlagsHostWhenThresholdExceeded(t *testing.T) {
	d := NewDetector(2)
	d.Record("host1", "tmplA")
	if d.IsFlagged("host1") {
		t.Errorf("host should not be flagged after 1 record")
	}
	d.Record("host1", "tmplB")
	if d.IsFlagged("host1") {
		t.Errorf("host should not be flagged exactly at threshold")
	}
	d.Record("host1", "tmplC")
	if !d.IsFlagged("host1") {
		t.Errorf("host should be flagged after exceeding threshold")
	}
}

func TestDetector_DoesNotFlagWhenDisabled(t *testing.T) {
	d := NewDetector(0)
	d.Record("host2", "tmpl1")
	d.Record("host2", "tmpl2")
	d.Record("host2", "tmpl3")
	if d.IsFlagged("host2") {
		t.Errorf("detection disabled, host should never be flagged")
	}
}

func TestDetector_ConcurrentRecording(t *testing.T) {
	d := NewDetector(50)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := "concurrent"
			tmpl := fmt.Sprintf("t%d", i)
			d.Record(host, tmpl)
		}(i)
	}
	wg.Wait()

	// 100 > threshold (50) so host must be flagged
	if !d.IsFlagged("concurrent") {
		t.Errorf("host should be flagged after concurrent recordings exceeding threshold")
	}
}