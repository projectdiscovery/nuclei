package progress

import (
	"context"
	"time"

	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/gologger"
)

// Progress is an interface implemented by nuclei progress display
// driver.
type Progress interface {
	// Stop stops the progress recorder.
	Stop()
	// Init inits the progress bar with initial details for scan
	Init(hostCount int64, rulesCount int, requestCount int64)
	// AddToTotal adds a value to the total request count
	AddToTotal(delta int64)
	// IncrementRequests increments the requests counter by 1.
	IncrementRequests()
	// SetRequests sets the counter by incrementing it with a delta
	SetRequests(count uint64)
	// IncrementMatched increments the matched counter by 1.
	IncrementMatched()
	// IncrementErrorsBy increments the error counter by count.
	IncrementErrorsBy(count int64)
	// IncrementFailedRequestsBy increments the number of requests counter by count
	// along with errors.
	IncrementFailedRequestsBy(count int64)
}

var _ Progress = &Stats{}

// Stats is a progress instance for showing program stats
type Stats struct {
	cloud bool
	stats clistats.StatisticsClient
}

// NewStats creates and returns a new progress tracking object.
func NewStats(cloud bool, port int) (Progress, error) {
	progress := &Stats{}

	options := clistats.DefaultOptions
	if port > 0 {
		options.ListenPort = port
	}
	stats, err := clistats.NewWithOptions(context.Background(), &options)
	if err != nil {
		return nil, err
	}
	progress.cloud = cloud
	progress.stats = stats

	return progress, nil
}

// Init initializes the progress display mechanism by setting counters, etc.
func (p *Stats) Init(hostCount int64, rulesCount int, requestCount int64) {
	p.stats.AddStatic("templates", rulesCount)
	p.stats.AddStatic("hosts", hostCount)
	p.stats.AddStatic("startedAt", time.Now())
	p.stats.AddCounter("requests", uint64(0))
	p.stats.AddCounter("errors", uint64(0))
	p.stats.AddCounter("matched", uint64(0))
	p.stats.AddCounter("total", uint64(requestCount))

	if err := p.stats.Start(); err != nil {
		gologger.Warning().Msgf("Couldn't start statistics: %s", err)
	}
}

// AddToTotal adds a value to the total request count
func (p *Stats) AddToTotal(delta int64) {
	p.stats.IncrementCounter("total", int(delta))
}

// IncrementRequests increments the requests counter by 1.
func (p *Stats) IncrementRequests() {
	p.stats.IncrementCounter("requests", 1)
}

// SetRequests sets the counter by incrementing it with a delta
func (p *Stats) SetRequests(count uint64) {
	value, _ := p.stats.GetCounter("requests")
	delta := count - value
	p.stats.IncrementCounter("requests", int(delta))
}

// IncrementMatched increments the matched counter by 1.
func (p *Stats) IncrementMatched() {
	p.stats.IncrementCounter("matched", 1)
}

// IncrementErrorsBy increments the error counter by count.
func (p *Stats) IncrementErrorsBy(count int64) {
	p.stats.IncrementCounter("errors", int(count))
}

// IncrementFailedRequestsBy increments the number of requests counter by count along with errors.
func (p *Stats) IncrementFailedRequestsBy(count int64) {
	// mimic dropping by incrementing the completed requests
	p.stats.IncrementCounter("requests", int(count))
	p.stats.IncrementCounter("errors", int(count))
}

// Stop stops the progress bar execution
func (p *Stats) Stop() {
	if err := p.stats.Stop(); err != nil {
		gologger.Warning().Msgf("Couldn't stop statistics: %s", err)
	}
}
