package progress

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
	"os"
	"strings"
	"sync"
)

// Encapsulates progress tracking.
type Progress struct {
	progress        *mpb.Progress
	gbar            *mpb.Bar
	total           int64
	initialTotal    int64
	totalMutex      *sync.Mutex
	captureData     *captureData
	stdCaptureMutex *sync.Mutex
	stdout          *strings.Builder
	stderr          *strings.Builder
	colorizer       aurora.Aurora
}

// Creates and returns a new progress tracking object.
func NewProgress(noColor bool) *Progress {
	p := &Progress{
		progress: mpb.New(
			mpb.WithOutput(os.Stderr),
			mpb.PopCompletedMode(),
		),
		totalMutex:      &sync.Mutex{},
		stdCaptureMutex: &sync.Mutex{},
		stdout:          &strings.Builder{},
		stderr:          &strings.Builder{},
		colorizer:       aurora.NewAurora(!noColor),
	}
	return p
}

// Creates and returns a progress bar that tracks all the requests progress.
// This is only useful when multiple templates are processed within the same run.
func (p *Progress) InitProgressbar(hostCount int64, templateCount int, requestCount int64) {
	if p.gbar != nil {
		panic("A global progressbar is already present.")
	}

	color := p.colorizer

	barName := color.Sprintf(
		color.Cyan("%d %s, %d %s"),
		color.Bold(color.Cyan(templateCount)),
		pluralize(int64(templateCount), "template", "templates"),
		color.Bold(color.Cyan(hostCount)),
		pluralize(hostCount, "host", "hosts"))

	p.gbar = p.setupProgressbar("["+barName+"]", requestCount, 0)
}

func pluralize(count int64, singular, plural string) string {
	if count > 1 {
		return plural
	}
	return singular
}

// Update total progress request count
func (p *Progress) AddToTotal(delta int64) {
	p.totalMutex.Lock()
	p.total += delta
	p.gbar.SetTotal(p.total, false)
	p.totalMutex.Unlock()
}

// Update progress tracking information and increments the request counter by one unit.
func (p *Progress) Update() {
	p.gbar.Increment()
}

// Drops the specified number of requests from the progress bar total.
// This may be the case when uncompleted requests are encountered and shouldn't be part of the total count.
func (p *Progress) Drop(count int64) {
	// mimic dropping by incrementing the completed requests
	p.gbar.IncrInt64(count)

}

// Ensures that a progress bar's total count is up-to-date if during an enumeration there were uncompleted requests and
// wait for all the progress bars to finish.
func (p *Progress) Wait() {
	p.totalMutex.Lock()
	if p.total == 0 {
		p.gbar.Abort(true)
	} else if p.initialTotal != p.total {
		p.gbar.SetTotal(p.total, true)
	}
	p.totalMutex.Unlock()
	p.progress.Wait()
}

// Creates and returns a progress bar.
func (p *Progress) setupProgressbar(name string, total int64, priority int) *mpb.Bar {
	color := p.colorizer

	p.total = total
	p.initialTotal = total

	return p.progress.AddBar(
		total,
		mpb.BarPriority(priority),
		mpb.BarNoPop(),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(name, decor.WCSyncSpaceR),
			decor.CountersNoUnit(color.BrightBlue(" %d/%d").String(), decor.WCSyncSpace),
			decor.NewPercentage(color.Bold("%d").String(), decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.AverageSpeed(0, color.BrightYellow("%.2f").Bold().String()+color.BrightYellow("r/s").String(), decor.WCSyncSpace),
			decor.Elapsed(decor.ET_STYLE_GO, decor.WCSyncSpace),
			decor.AverageETA(decor.ET_STYLE_GO, decor.WCSyncSpace),
		),
	)
}

// Starts capturing stdout and stderr instead of producing visual output that may interfere with the progress bars.
func (p *Progress) StartStdCapture() {
	p.stdCaptureMutex.Lock()
	p.captureData = startStdCapture()
}

// Stops capturing stdout and stderr and store both output to be shown later.
func (p *Progress) StopStdCapture() {
	stopStdCapture(p.captureData)
	p.stdout.Write(p.captureData.DataStdOut.Bytes())
	p.stderr.Write(p.captureData.DataStdErr.Bytes())
	p.stdCaptureMutex.Unlock()
}

// Writes the captured stdout data to stdout, if any.
func (p *Progress) ShowStdOut() {
	if p.stdout.Len() > 0 {
		fmt.Fprint(os.Stdout, p.stdout.String())
	}
}

// Writes the captured stderr data to stderr, if any.
func (p *Progress) ShowStdErr() {
	if p.stderr.Len() > 0 {
		fmt.Fprint(os.Stderr, p.stderr.String())
	}
}
