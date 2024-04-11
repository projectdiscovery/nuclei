package events

import (
	"time"
)

type ScanEventWorker interface {
	// AddScanEvent adds a scan event to the worker
	AddScanEvent(event ScanEvent)
}

// Track scan start / finish status
type ScanStatus string

const (
	ScanStarted  ScanStatus = "scan_start"
	ScanFinished ScanStatus = "scan_end"
)

const (
	ConfigFile = "config.json"
	EventsFile = "events.jsonl"
)

// ScanEvent represents a single scan event with its metadata
type ScanEvent struct {
	Target       string     `json:"target" yaml:"target"`
	TemplateType string     `json:"template_type" yaml:"template_type"`
	TemplateID   string     `json:"template_id" yaml:"template_id"`
	TemplatePath string     `json:"template_path" yaml:"template_path"`
	MaxRequests  int        `json:"max_requests" yaml:"max_requests"`
	Time         time.Time  `json:"time" yaml:"time"`
	EventType    ScanStatus `json:"event_type" yaml:"event_type"`
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
