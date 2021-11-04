package progress

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	// IncrementMatched increments the matched counter by 1.
	IncrementMatched()
	// IncrementErrorsBy increments the error counter by count.
	IncrementErrorsBy(count int64)
	// IncrementFailedRequestsBy increments the number of requests counter by count
	// along with errors.
	IncrementFailedRequestsBy(count int64)
}

var _ Progress = &StatsTicker{}

// StatsTicker is a progress instance for showing program stats
type StatsTicker struct {
	active       bool
	outputJSON   bool
	server       *http.Server
	stats        clistats.StatisticsClient
	tickDuration time.Duration
}

// NewStatsTicker creates and returns a new progress tracking object.
func NewStatsTicker(duration int, active, outputJSON, metrics bool, port int) (Progress, error) {
	var tickDuration time.Duration
	if active {
		tickDuration = time.Duration(duration) * time.Second
	} else {
		tickDuration = -1
	}

	progress := &StatsTicker{}

	stats, err := clistats.New()
	if err != nil {
		return nil, err
	}
	progress.active = active
	progress.stats = stats
	progress.tickDuration = tickDuration
	progress.outputJSON = outputJSON

	if metrics {
		http.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
			metrics := progress.getMetrics()
			_ = json.NewEncoder(w).Encode(metrics)
		})
		progress.server = &http.Server{
			Addr:    net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			Handler: http.DefaultServeMux,
		}
		go func() {
			if err := progress.server.ListenAndServe(); err != nil {
				gologger.Warning().Msgf("Could not serve metrics: %s", err)
			}
		}()
	}
	return progress, nil
}

// Init initializes the progress display mechanism by setting counters, etc.
func (p *StatsTicker) Init(hostCount int64, rulesCount int, requestCount int64) {
	p.stats.AddStatic("templates", rulesCount)
	p.stats.AddStatic("hosts", hostCount)
	p.stats.AddStatic("startedAt", time.Now())
	p.stats.AddCounter("requests", uint64(0))
	p.stats.AddCounter("errors", uint64(0))
	p.stats.AddCounter("matched", uint64(0))
	p.stats.AddCounter("total", uint64(requestCount))

	if p.active {
		var printCallbackFunc clistats.PrintCallback
		if p.outputJSON {
			printCallbackFunc = printCallbackJSON
		} else {
			printCallbackFunc = printCallback
		}
		if err := p.stats.Start(printCallbackFunc, p.tickDuration); err != nil {
			gologger.Warning().Msgf("Couldn't start statistics: %s", err)
		}
	}
}

// AddToTotal adds a value to the total request count
func (p *StatsTicker) AddToTotal(delta int64) {
	p.stats.IncrementCounter("total", int(delta))
}

// IncrementRequests increments the requests counter by 1.
func (p *StatsTicker) IncrementRequests() {
	p.stats.IncrementCounter("requests", 1)
}

// IncrementMatched increments the matched counter by 1.
func (p *StatsTicker) IncrementMatched() {
	p.stats.IncrementCounter("matched", 1)
}

// IncrementErrorsBy increments the error counter by count.
func (p *StatsTicker) IncrementErrorsBy(count int64) {
	p.stats.IncrementCounter("errors", int(count))
}

// IncrementFailedRequestsBy increments the number of requests counter by count along with errors.
func (p *StatsTicker) IncrementFailedRequestsBy(count int64) {
	// mimic dropping by incrementing the completed requests
	p.stats.IncrementCounter("requests", int(count))
	p.stats.IncrementCounter("errors", int(count))
}

func printCallback(stats clistats.StatisticsClient) {
	builder := &strings.Builder{}
	builder.WriteRune('[')
	startedAt, _ := stats.GetStatic("startedAt")
	duration := time.Since(startedAt.(time.Time))
	builder.WriteString(fmtDuration(duration))
	builder.WriteRune(']')

	templates, _ := stats.GetStatic("templates")
	builder.WriteString(" | Templates: ")
	builder.WriteString(clistats.String(templates))
	hosts, _ := stats.GetStatic("hosts")
	builder.WriteString(" | Hosts: ")
	builder.WriteString(clistats.String(hosts))

	requests, _ := stats.GetCounter("requests")
	total, _ := stats.GetCounter("total")

	builder.WriteString(" | RPS: ")
	builder.WriteString(clistats.String(uint64(float64(requests) / duration.Seconds())))

	matched, _ := stats.GetCounter("matched")

	builder.WriteString(" | Matched: ")
	builder.WriteString(clistats.String(matched))

	errors, _ := stats.GetCounter("errors")
	builder.WriteString(" | Errors: ")
	builder.WriteString(clistats.String(errors))

	builder.WriteString(" | Requests: ")
	builder.WriteString(clistats.String(requests))
	builder.WriteRune('/')
	builder.WriteString(clistats.String(total))
	builder.WriteRune(' ')
	builder.WriteRune('(')
	//nolint:gomnd // this is not a magic number
	builder.WriteString(clistats.String(uint64(float64(requests) / float64(total) * 100.0)))
	builder.WriteRune('%')
	builder.WriteRune(')')
	builder.WriteRune('\n')

	fmt.Fprintf(os.Stderr, "%s", builder.String())
}

func printCallbackJSON(stats clistats.StatisticsClient) {
	builder := &strings.Builder{}
	_ = json.NewEncoder(builder).Encode(metricsMap(stats))
	fmt.Fprintf(os.Stderr, "%s", builder.String())
}

func metricsMap(stats clistats.StatisticsClient) map[string]interface{} {
	results := make(map[string]interface{})

	startedAt, _ := stats.GetStatic("startedAt")
	duration := time.Since(startedAt.(time.Time))

	results["startedAt"] = startedAt.(time.Time)
	results["duration"] = fmtDuration(duration)
	templates, _ := stats.GetStatic("templates")
	results["templates"] = clistats.String(templates)
	hosts, _ := stats.GetStatic("hosts")
	results["hosts"] = clistats.String(hosts)
	matched, _ := stats.GetCounter("matched")
	results["matched"] = clistats.String(matched)
	requests, _ := stats.GetCounter("requests")
	results["requests"] = clistats.String(requests)
	total, _ := stats.GetCounter("total")
	results["total"] = clistats.String(total)
	results["rps"] = clistats.String(uint64(float64(requests) / duration.Seconds()))
	errors, _ := stats.GetCounter("errors")
	results["errors"] = clistats.String(errors)

	//nolint:gomnd // this is not a magic number
	percentData := (float64(requests) * float64(100)) / float64(total)
	percent := clistats.String(uint64(percentData))
	results["percent"] = percent
	return results
}

// getMetrics returns a map of important metrics for client
func (p *StatsTicker) getMetrics() map[string]interface{} {
	return metricsMap(p.stats)
}

// fmtDuration formats the duration for the time elapsed
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	return fmt.Sprintf("%d:%02d:%02d", h, m, s)
}

// Stop stops the progress bar execution
func (p *StatsTicker) Stop() {
	if p.active {
		// Print one final summary
		if p.outputJSON {
			printCallbackJSON(p.stats)
		} else {
			printCallback(p.stats)
		}
		if err := p.stats.Stop(); err != nil {
			gologger.Warning().Msgf("Couldn't stop statistics: %s", err)
		}
	}
	if p.server != nil {
		_ = p.server.Shutdown(context.Background())
	}
}
