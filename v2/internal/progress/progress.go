package progress

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	RefreshHz     = 4.
	RefreshMillis = int64((1. / RefreshHz) * 1000.)
)

// Encapsulates progress tracking.
type IProgress interface {
	InitProgressbar(hostCount int64, templateCount int, requestCount int64)
	AddToTotal(delta int64)
	Update()
	render()
	Drop(count int64)
	Wait()
	StartStdCapture()
	StopStdCapture()
}

type Progress struct {
	progress        *mpb.Progress
	bar             *mpb.Bar
	total           int64
	initialTotal    int64
	totalMutex      *sync.Mutex
	captureData     *captureData
	stdCaptureMutex *sync.Mutex
	stdout          *strings.Builder
	stderr          *strings.Builder
	colorizer       aurora.Aurora
	renderChan      chan time.Time
	renderMutex     *sync.Mutex
	renderTime      time.Time
	firstTimeOutput bool
}

// Creates and returns a new progress tracking object.
func NewProgress(noColor bool, active bool) IProgress {
	if !active {
		return &NoOpProgress{}
	}

	renderChan := make(chan time.Time)
	p := &Progress{
		progress: mpb.New(
			mpb.WithOutput(os.Stderr),
			mpb.PopCompletedMode(),
			mpb.WithManualRefresh(renderChan),
		),
		totalMutex:      &sync.Mutex{},
		stdCaptureMutex: &sync.Mutex{},
		stdout:          &strings.Builder{},
		stderr:          &strings.Builder{},
		colorizer:       aurora.NewAurora(!noColor),
		renderChan:      renderChan,
		renderMutex:     &sync.Mutex{},
		renderTime:      time.Now(),
		firstTimeOutput: true,
	}
	return p
}

// Creates and returns a progress bar that tracks all the requests progress.
// This is only useful when multiple templates are processed within the same run.
func (p *Progress) InitProgressbar(hostCount int64, templateCount int, requestCount int64) {
	if p.bar != nil {
		panic("A global progressbar is already present.")
	}

	color := p.colorizer

	barName := color.Sprintf(
		color.Cyan("%d %s, %d %s"),
		color.Bold(color.Cyan(templateCount)),
		pluralize(int64(templateCount), "template", "templates"),
		color.Bold(color.Cyan(hostCount)),
		pluralize(hostCount, "host", "hosts"))

	p.bar = p.setupProgressbar("["+barName+"]", requestCount, 0)
}

// Update total progress request count
func (p *Progress) AddToTotal(delta int64) {
	p.totalMutex.Lock()
	p.total += delta
	p.bar.SetTotal(p.total, false)
	p.totalMutex.Unlock()
}

// Update progress tracking information and increments the request counter by one unit.
func (p *Progress) Update() {
	p.bar.Increment()
	p.render()
}

// Drops the specified number of requests from the progress bar total.
// This may be the case when uncompleted requests are encountered and shouldn't be part of the total count.
func (p *Progress) Drop(count int64) {
	// mimic dropping by incrementing the completed requests
	p.bar.IncrInt64(count)
	p.render()
}

// Ensures that a progress bar's total count is up-to-date if during an enumeration there were uncompleted requests and
// wait for all the progress bars to finish.
func (p *Progress) Wait() {
	p.totalMutex.Lock()
	if p.total == 0 {
		p.bar.Abort(true)
	} else if p.initialTotal != p.total {
		p.bar.SetTotal(p.total, true)
	}
	p.totalMutex.Unlock()
	p.progress.Wait()

	// drain any stdout/stderr data
	p.drainStringBuilderTo(p.stdout, os.Stdout)
	p.drainStringBuilderTo(p.stderr, os.Stderr)
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

	p.renderMutex.Lock()
	{
		hasStdout := p.stdout.Len() > 0
		hasStderr := p.stderr.Len() > 0
		hasOutput := hasStdout || hasStderr

		if hasOutput {
			if p.firstTimeOutput {
				// trigger a render event
				p.renderChan <- time.Now()
				gologger.Infof("Waiting for your terminal to settle..")
				// no way to sync to it? :(
				time.Sleep(time.Millisecond * 250)
				p.firstTimeOutput = false
			}

			if can, now := p.canRender(); can {
				// go back one line and clean it all
				fmt.Fprint(os.Stderr, "\u001b[1A\u001b[2K")
				p.drainStringBuilderTo(p.stdout, os.Stdout)
				p.drainStringBuilderTo(p.stderr, os.Stderr)

				// make space for the progressbar to render itself
				fmt.Fprintln(os.Stderr, "")

				// always trigger a render event to try ensure it's visible even with fast output
				p.renderChan <- now
				p.renderTime = now
			}
		}
	}
	p.renderMutex.Unlock()
	p.stdCaptureMutex.Unlock()
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

func (p *Progress) render() {
	p.renderMutex.Lock()
	if can, now := p.canRender(); can {
		p.renderChan <- now
		p.renderTime = now
	}
	p.renderMutex.Unlock()
}

func (p *Progress) canRender() (bool, time.Time) {
	now := time.Now()
	if now.Sub(p.renderTime).Milliseconds() >= RefreshMillis {
		return true, now
	}
	return false, now
}

func pluralize(count int64, singular, plural string) string {
	if count > 1 {
		return plural
	}
	return singular
}

func (p *Progress) drainStringBuilderTo(builder *strings.Builder, writer io.Writer) {
	if builder.Len() > 0 {
		fmt.Fprint(writer, builder.String())
		builder.Reset()
	}
}
