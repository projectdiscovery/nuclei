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
	progress    *mpb.Progress
	barTemplate *Bar
	barGlobal   *Bar

	captureData     *captureData
	stdCaptureMutex *sync.Mutex
	stdout          *strings.Builder
	stderr          *strings.Builder
}

// Creates and returns a new progress tracking object.
func NewProgress(group *sync.WaitGroup) *Progress {
	p := &Progress{
		progress: mpb.New(
			mpb.WithWaitGroup(group),
			mpb.WithOutput(os.Stderr),
			mpb.PopCompletedMode(),
		),
		stdCaptureMutex: &sync.Mutex{},
		stdout:          &strings.Builder{},
		stderr:          &strings.Builder{},
	}
	return p
}

// Creates and returns a progress bar that tracks request progress for a specific template.
func (p *Progress) SetupTemplateProgressbar(templateIndex int, templateCount int, name string, requestCount int64) {
	barName := "[" + aurora.Green(name).String() + "]"

	if templateIndex > -1 && templateCount > -1 {
		barName = aurora.Sprintf("[%d/%d] ", aurora.Bold(aurora.Cyan(templateIndex)), aurora.Cyan(templateCount)) + barName
	}

	bar := p.setupProgressbar(barName, requestCount)

	if p.barTemplate != nil {
		// ensure any previous bar has finished and dropped requests have also been considered
		p.barTemplate.finish()
	}

	p.barTemplate = &Bar{
		bar:          bar,
		total:        requestCount,
		initialTotal: requestCount,
	}
}

// Creates and returns a progress bar that tracks all the requests progress.
// This is only useful when multiple templates are processed within the same run.
func (p *Progress) SetupGlobalProgressbar(hostCount int64, templateCount int, requestCount int64) {
	hostPlural := "host"
	if hostCount > 1 {
		hostPlural = "hosts"
	}

	barName := "[" + aurora.Sprintf(
		aurora.Cyan("%d templates, %d %s"),
		aurora.Bold(aurora.Cyan(templateCount)),
		aurora.Bold(aurora.Cyan(hostCount)),
		hostPlural) + "]"

	bar := p.setupProgressbar(barName, requestCount)

	p.barGlobal = &Bar{
		bar:          bar,
		total:        requestCount,
		initialTotal: requestCount,
	}
}

// Update progress tracking information and increments the request counter by one unit.
// If a global progress bar is present it will be updated as well.
func (p *Progress) Update() {
	p.barTemplate.bar.Increment()

	if p.barGlobal != nil {
		p.barGlobal.bar.Increment()
	}
}

// Drops the specified number of requests from the progress bar total.
// This may be the case when uncompleted requests are encountered and shouldn't be part of the total count.
// If a global progress bar is present it will be updated as well.
func (p *Progress) Drop(count int64) {
	p.barTemplate.Drop(count)

	if p.barGlobal != nil {
		p.barGlobal.Drop(count)
	}
}

// Ensures that a progress bar's total count is up-to-date if during an enumeration there were uncompleted requests and
// wait for all the progress bars to finish.
// If a global progress bar is present it will be updated as well.
func (p *Progress) Wait() {
	p.barTemplate.finish()

	if p.barGlobal != nil {
		p.barGlobal.finish()
	}

	p.progress.Wait()
}

// Creates and returns a progress bar.
func (p *Progress) setupProgressbar(name string, total int64) *mpb.Bar {
	return p.progress.AddBar(
		total,
		mpb.BarNoPop(),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(name, decor.WCSyncSpaceR),
			decor.CountersNoUnit(aurora.Blue(" %d/%d").String(), decor.WCSyncSpace),
			decor.NewPercentage(aurora.Bold("%d").String(), decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.AverageSpeed(0, aurora.Yellow("%.2f r/s ").String(), decor.WCSyncSpace),
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
