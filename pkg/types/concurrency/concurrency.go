package concurrency

import "time"

// Concurrency options
type Concurrency struct {
	TemplateConcurrency           int // number of templates to run concurrently (per host in host-spray mode)
	HostConcurrency               int // number of hosts to scan concurrently  (per template in template-spray mode)
	HeadlessHostConcurrency       int // number of hosts to scan concurrently for headless templates  (per template in template-spray mode)
	HeadlessTemplateConcurrency   int // number of templates to run concurrently for headless templates (per host in host-spray mode)
	JavascriptTemplateConcurrency int // number of templates to run concurrently for javascript templates (per host in host-spray mode)
	TemplatePayloadConcurrency    int // max concurrent payloads to run for a template (a good default is 25)
	RateLimitMax                  int
	RateLimitDuration             time.Duration
}
