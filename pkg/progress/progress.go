package progress

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
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

// TaskTracker is implemented by a Progress that also counts template
// executions. The engine counts one task for each template it runs on a
// target, and one for each self-contained template. Unlike the request total,
// which is an estimate, the task total is known when the scan starts, so it
// gives an exact completion percentage.
type TaskTracker interface {
	// AddToTaskTotal adds delta to the number of tasks the scan will run.
	AddToTaskTotal(delta int64)
	// IncrementTasksBy marks count tasks as done.
	IncrementTasksBy(count int64)
}

var (
	_ Progress    = &StatsTicker{}
	_ TaskTracker = &StatsTicker{}
)

// StatsTicker is a progress instance for showing program stats
type StatsTicker struct {
	cloud        bool
	active       bool
	outputJSON   bool
	stats        clistats.StatisticsClient
	tickDuration time.Duration
}

// NewStatsTicker creates and returns a new progress tracking object.
func NewStatsTicker(duration int, active, outputJSON, cloud bool, port int) (Progress, error) {
	var tickDuration time.Duration
	if active && duration != -1 {
		tickDuration = time.Duration(duration) * time.Second
	} else {
		tickDuration = -1
	}

	progress := &StatsTicker{}

	statsOpts := &clistats.DefaultOptions
	statsOpts.ListenPort = port
	// metrics port is enabled by default and is not configurable with new version of clistats
	// by default 63636 is used and than can be modified with -mp flag

	stats, err := clistats.NewWithOptions(context.TODO(), statsOpts)
	if err != nil {
		return nil, err
	}
	// only print in verbose mode
	gologger.Verbose().Msgf("Started metrics server at localhost:%v", stats.Options.ListenPort)
	progress.cloud = cloud
	progress.active = active
	progress.stats = stats
	progress.tickDuration = tickDuration
	progress.outputJSON = outputJSON

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
	p.stats.AddCounter("tasks", uint64(0))
	p.stats.AddCounter("totalTasks", uint64(0))
	// the metrics endpoint serves it once clistats keeps the fields its
	// caller provides; until then it serves requests/total
	p.stats.AddDynamic("percent", func(stats clistats.StatisticsClient) interface{} {
		return clistats.String(scanPercent(stats))
	})

	if p.active {
		var printCallbackFunc clistats.DynamicCallback
		if p.outputJSON {
			printCallbackFunc = printCallbackJSON
		} else {
			printCallbackFunc = p.makePrintCallback()
		}
		p.stats.AddDynamic("summary", printCallbackFunc)
		if err := p.stats.Start(); err != nil {
			gologger.Warning().Msgf("Couldn't start statistics: %s", err)
		}

		if p.tickDuration > 0 {
			// Note: this is needed and is responsible for the tick event
			p.stats.GetStatResponse(p.tickDuration, func(s string, err error) error {
				if err != nil {
					gologger.Warning().Msgf("Could not read statistics: %s\n", err)
				}
				return nil
			})
		}
	}
}

// AddToTotal adds a value to the total request count
func (p *StatsTicker) AddToTotal(delta int64) {
	p.stats.IncrementCounter("total", int(delta))
}

// AddToTaskTotal adds delta to the number of tasks the scan will run.
func (p *StatsTicker) AddToTaskTotal(delta int64) {
	p.stats.IncrementCounter("totalTasks", int(delta))
}

// IncrementTasksBy marks count tasks as done.
func (p *StatsTicker) IncrementTasksBy(count int64) {
	p.stats.IncrementCounter("tasks", int(count))
}

// IncrementRequests increments the requests counter by 1.
func (p *StatsTicker) IncrementRequests() {
	p.stats.IncrementCounter("requests", 1)
}

// SetRequests sets the counter by incrementing it with a delta
func (p *StatsTicker) SetRequests(count uint64) {
	p.stats.IncrementCounter("requests", int(count))
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

func (p *StatsTicker) makePrintCallback() func(stats clistats.StatisticsClient) interface{} {
	return func(stats clistats.StatisticsClient) interface{} {
		builder := &strings.Builder{}

		var duration time.Duration
		if startedAt, ok := stats.GetStatic("startedAt"); ok {
			if startedAtTime, ok := startedAt.(time.Time); ok {
				duration = time.Since(startedAtTime)
				_, _ = fmt.Fprintf(builder, "[%s]", fmtDuration(duration))
			}
		}

		if templates, ok := stats.GetStatic("templates"); ok {
			builder.WriteString(" | Templates: ")
			builder.WriteString(clistats.String(templates))
		}

		if hosts, ok := stats.GetStatic("hosts"); ok {
			builder.WriteString(" | Hosts: ")
			builder.WriteString(clistats.String(hosts))
		}

		requests, okRequests := stats.GetCounter("requests")
		total, okTotal := stats.GetCounter("total")

		// If input is not given, total is 0 which cause percentage overflow
		if total == 0 {
			total = requests
		}

		if okRequests && okTotal && duration > 0 && !p.cloud {
			builder.WriteString(" | RPS: ")
			builder.WriteString(clistats.String(uint64(float64(requests) / duration.Seconds())))
		}

		if matched, ok := stats.GetCounter("matched"); ok {
			builder.WriteString(" | Matched: ")
			builder.WriteString(clistats.String(matched))
		}

		if errors, ok := stats.GetCounter("errors"); ok && !p.cloud {
			builder.WriteString(" | Errors: ")
			builder.WriteString(clistats.String(errors))
		}

		if okRequests && okTotal {
			if p.cloud {
				builder.WriteString(" | Task: ")
			} else {
				builder.WriteString(" | Requests: ")
			}
			builder.WriteString(clistats.String(requests))
			builder.WriteRune('/')
			builder.WriteString(clistats.String(total))
			percent := percentComplete(requests, total)
			if tasks, totalTasks, ok := taskCounts(stats); ok {
				builder.WriteString(" | Tasks: ")
				builder.WriteString(clistats.String(tasks))
				builder.WriteRune('/')
				builder.WriteString(clistats.String(totalTasks))
				percent = percentComplete(tasks, totalTasks)
			}
			builder.WriteRune(' ')
			builder.WriteRune('(')
			builder.WriteString(clistats.String(percent))
			builder.WriteRune('%')
			builder.WriteRune(')')
			builder.WriteRune('\n')
		}

		_, _ = fmt.Fprintf(os.Stderr, "%s", builder.String())
		return builder.String()
	}
}

func printCallbackJSON(stats clistats.StatisticsClient) interface{} {
	builder := &strings.Builder{}
	if err := json.NewEncoder(builder).Encode(metricsMap(stats)); err == nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s", builder.String())
	}
	return builder.String()
}

func metricsMap(stats clistats.StatisticsClient) map[string]interface{} {
	results := make(map[string]interface{})

	var (
		startedAt time.Time
		duration  time.Duration
	)

	if stAt, ok := stats.GetStatic("startedAt"); ok {
		startedAt = stAt.(time.Time)
		duration = time.Since(startedAt)
	}

	results["startedAt"] = startedAt
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
	tasks, _ := stats.GetCounter("tasks")
	results["tasks"] = clistats.String(tasks)
	totalTasks, _ := stats.GetCounter("totalTasks")
	results["totalTasks"] = clistats.String(totalTasks)

	results["percent"] = clistats.String(scanPercent(stats))
	return results
}

// taskCounts returns the done and total tasks when the scan counts tasks.
func taskCounts(stats clistats.StatisticsClient) (tasks, totalTasks uint64, ok bool) {
	totalTasks, _ = stats.GetCounter("totalTasks")
	if totalTasks == 0 {
		return 0, 0, false
	}
	tasks, _ = stats.GetCounter("tasks")
	return tasks, totalTasks, true
}

// scanPercent returns the completed share of the scan, from tasks when they
// are counted and from requests otherwise.
func scanPercent(stats clistats.StatisticsClient) uint64 {
	if tasks, totalTasks, ok := taskCounts(stats); ok {
		return percentComplete(tasks, totalTasks)
	}
	requests, _ := stats.GetCounter("requests")
	total, _ := stats.GetCounter("total")
	return percentComplete(requests, total)
}

func percentComplete(done, total uint64) uint64 {
	if total == 0 {
		return 0
	}
	// nolint:gomnd // this is not a magic number
	return uint64((float64(done) * float64(100)) / float64(total))
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
			p.makePrintCallback()(p.stats)
		}
		if err := p.stats.Stop(); err != nil {
			gologger.Warning().Msgf("Couldn't stop statistics: %s", err)
		}
	}
}
