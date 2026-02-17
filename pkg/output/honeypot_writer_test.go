package output

import (
	"testing"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
)

type mockWriter struct {
	events  []*ResultEvent
	closed  bool
	results int
}

func (m *mockWriter) Close()                                                        { m.closed = true }
func (m *mockWriter) Colorizer() aurora.Aurora                                       { return aurora.NewAurora(false) }
func (m *mockWriter) Write(event *ResultEvent) error                                 { m.events = append(m.events, event); m.results++; return nil }
func (m *mockWriter) WriteFailure(event *InternalWrappedEvent) error                 { return nil }
func (m *mockWriter) Request(templateID, url, requestType string, err error)         {}
func (m *mockWriter) RequestStatsLog(statusCode, response string)                    {}
func (m *mockWriter) WriteStoreDebugData(host, templateID, eventType string, d string) {}
func (m *mockWriter) ResultCount() int                                               { return m.results }

func TestHoneypotWriterDetection(t *testing.T) {
	mock := &mockWriter{}
	hw := NewHoneypotWriter(HoneypotWriterOptions{
		Inner:     mock,
		Threshold: 3,
		Logger:    gologger.DefaultLogger,
	})

	// Write 3 unique template matches for the same host
	for i := 0; i < 3; i++ {
		event := &ResultEvent{
			Host:       "192.168.1.1",
			TemplateID: "template-" + string(rune('a'+i)),
		}
		if err := hw.Write(event); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	detected := hw.GetDetectedHoneypots()
	if len(detected) != 1 {
		t.Fatalf("expected 1 detected honeypot, got %d", len(detected))
	}
	if detected["192.168.1.1"] != 3 {
		t.Fatalf("expected 3 matches for host, got %d", detected["192.168.1.1"])
	}

	// All results should have been written through (exclude=false)
	if len(mock.events) != 3 {
		t.Fatalf("expected 3 events written, got %d", len(mock.events))
	}
}

func TestHoneypotWriterExclude(t *testing.T) {
	mock := &mockWriter{}
	hw := NewHoneypotWriter(HoneypotWriterOptions{
		Inner:          mock,
		Threshold:      3,
		ExcludeResults: true,
		Logger:         gologger.DefaultLogger,
	})

	// Write 5 unique template matches for the same host
	for i := 0; i < 5; i++ {
		event := &ResultEvent{
			Host:       "10.0.0.1",
			TemplateID: "tmpl-" + string(rune('a'+i)),
		}
		_ = hw.Write(event)
	}

	detected := hw.GetDetectedHoneypots()
	if len(detected) != 1 {
		t.Fatalf("expected 1 detected honeypot, got %d", len(detected))
	}

	// When exclude is enabled, results at and above threshold should be dropped.
	// Templates a, b are written (count 1, 2 -- below threshold 3)
	// Template c hits threshold exactly (count 3) -- dropped
	// Templates d, e exceed threshold -- dropped
	if len(mock.events) != 2 {
		t.Fatalf("expected 2 events written (below threshold), got %d", len(mock.events))
	}
}

func TestHoneypotWriterNoDetection(t *testing.T) {
	mock := &mockWriter{}
	hw := NewHoneypotWriter(HoneypotWriterOptions{
		Inner:     mock,
		Threshold: 10,
		Logger:    gologger.DefaultLogger,
	})

	// Write 3 unique template matches (below threshold)
	for i := 0; i < 3; i++ {
		event := &ResultEvent{
			Host:       "example.com",
			TemplateID: "t-" + string(rune('a'+i)),
		}
		_ = hw.Write(event)
	}

	detected := hw.GetDetectedHoneypots()
	if len(detected) != 0 {
		t.Fatalf("expected no detected honeypots, got %d", len(detected))
	}
	if len(mock.events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(mock.events))
	}
}

func TestHoneypotWriterMultipleHosts(t *testing.T) {
	mock := &mockWriter{}
	hw := NewHoneypotWriter(HoneypotWriterOptions{
		Inner:     mock,
		Threshold: 2,
		Logger:    gologger.DefaultLogger,
	})

	// Host A: 3 matches (honeypot)
	for i := 0; i < 3; i++ {
		_ = hw.Write(&ResultEvent{Host: "host-a", TemplateID: "t-" + string(rune('a'+i))})
	}
	// Host B: 1 match (normal)
	_ = hw.Write(&ResultEvent{Host: "host-b", TemplateID: "t-x"})

	detected := hw.GetDetectedHoneypots()
	if len(detected) != 1 {
		t.Fatalf("expected 1 detected honeypot, got %d", len(detected))
	}
	if _, ok := detected["host-a"]; !ok {
		t.Fatal("expected host-a to be detected as honeypot")
	}
	if _, ok := detected["host-b"]; ok {
		t.Fatal("host-b should not be detected as honeypot")
	}
}

func TestHoneypotWriterDuplicateTemplates(t *testing.T) {
	mock := &mockWriter{}
	hw := NewHoneypotWriter(HoneypotWriterOptions{
		Inner:     mock,
		Threshold: 3,
		Logger:    gologger.DefaultLogger,
	})

	// Same template matched multiple times should only count once
	for i := 0; i < 5; i++ {
		_ = hw.Write(&ResultEvent{Host: "host-c", TemplateID: "same-template"})
	}

	detected := hw.GetDetectedHoneypots()
	if len(detected) != 0 {
		t.Fatalf("expected no honeypot (same template repeated), got %d", len(detected))
	}
}

func TestHoneypotWriterClose(t *testing.T) {
	mock := &mockWriter{}
	hw := NewHoneypotWriter(HoneypotWriterOptions{
		Inner:     mock,
		Threshold: 5,
		Logger:    gologger.DefaultLogger,
	})

	hw.Close()
	if !mock.closed {
		t.Fatal("expected inner writer to be closed")
	}
}
