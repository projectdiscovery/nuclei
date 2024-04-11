package events

import (
	"encoding/json"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
)

type ScanEventWorker interface {
	// AddScanEvent adds a scan event to the worker
	AddScanEvent(event ScanEvent)
}

// Track scan start / finish status
type ScanStatus int

const (
	ScanStarted ScanStatus = iota
	ScanFinished
)

const (
	configFile = "config.json"
	eventsFile = "events.jsonl"
)

// ScanEvent represents a single scan event with its metadata
type ScanEvent struct {
	Target       string
	TemplateInfo model.Info
	Time         time.Time
	EventType    ScanStatus
}

// MarshalJSON implements the json.Marshaler interface
func (s ScanEvent) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["target"] = s.Target
	m["template"] = s.TemplateInfo
	m["time"] = s.Time
	if s.EventType == ScanStarted {
		m["event"] = "scan-start"
	} else {
		m["event"] = "scan-end"
	}
	return json.Marshal(m)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (s *ScanEvent) UnmarshalJSON(data []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	s.Target = m["target"].(string)
	s.TemplateInfo = m["template"].(model.Info)
	if t, ok := m["time"].(string); ok {
		s.Time, _ = time.Parse(time.RFC3339, t)
	}
	if m["event"] == "scan-start" {
		s.EventType = ScanStarted
	} else {
		s.EventType = ScanFinished
	}
	return nil
}

// ScanConfig is only in context of scan event analysis
type ScanConfig struct {
	Name                string `json:"name" yaml:"name"`
	TargetCount         int    `json:"target_count" yaml:"target_count"`
	TemplatesCount      int    `json:"templates_count" yaml:"templates_count"`
	TemplateConcurrency int    `json:"template_concurrency" yaml:"template_concurrency"`
	PayloadConcurrency  int    `json:"payload_concurrency" yaml:"payload_concurrency"`
	JsConcurrency       int    `json:"js_concurrency" yaml:"js_concurrency"`
	Retries             int    `json:"retries" yaml:"retries"`
}
