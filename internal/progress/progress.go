package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/decor"
)

const (
	// global output refresh rate
	refreshHz   = 8
	settleMilis = 250
	mili        = 1000.
)

// Encapsulates progress tracking.
type IProgress interface {
	InitProgressbar(hostCount int64, templateCount int, requestCount int64)
	AddToTotal(delta int64)
	Update()
	Drop(count int64)
	Wait()
}

type Progress struct {
	progress     *mpb.Progress
	bar          *mpb.Bar
	total        int64
	initialTotal int64

	totalMutex *sync.Mutex
	colorizer  aurora.Aurora

	renderChan         chan time.Time
	captureData        *captureData
	stdCaptureMutex    *sync.Mutex
	stdOut             *strings.Builder
	stdErr             *strings.Builder
	stdStopRenderEvent chan bool
	stdRenderEvent     *time.Ticker
	stdRenderWaitGroup *sync.WaitGroup
}

// Creates and returns a new progress tracking object.
func NewProgress(noColor, active bool) IProgress {
	if !active {
		return &NoOpProgress{}
	}

	refreshMillis := int64(1. / float64(refreshHz) * mili)

	renderChan := make(chan time.Time)
	p := &Progress{
		progress: mpb.New(
			mpb.WithOutput(os.Stderr),
			mpb.PopCompletedMode(),
			mpb.WithManualRefresh(renderChan),
		),
		totalMutex: &sync.Mutex{},
		colorizer:  aurora.NewAurora(!noColor),

		renderChan:         renderChan,
		stdCaptureMutex:    &sync.Mutex{},
		stdOut:             &strings.Builder{},
		stdErr:             &strings.Builder{},
		stdStopRenderEvent: make(chan bool),
		stdRenderEvent:     time.NewTicker(time.Millisecond * time.Duration(refreshMillis)),
		stdRenderWaitGroup: &sync.WaitGroup{},
	}

	return p
}

// Creates and returns a progress bar that tracks all the progress.
func (p *Progress) InitProgressbar(hostCount int64, rulesCount int, requestCount int64) {
	if p.bar != nil {
		panic("A global progressbar is already present.")
	}

	color := p.colorizer

	barName := color.Sprintf(
		color.Cyan("%d %s, %d %s"),
		color.Bold(color.Cyan(rulesCount)),
		pluralize(int64(rulesCount), "rule", "rules"),
		color.Bold(color.Cyan(hostCount)),
		pluralize(hostCount, "host", "hosts"))

	p.bar = p.setupProgressbar("["+barName+"]", requestCount, 0)

	// creates r/w pipes and divert stdout/stderr writers to them and start capturing their output
	p.captureData = startCapture(p.stdCaptureMutex, p.stdOut, p.stdErr)

	// starts rendering both the progressbar and the captured stdout/stderr data
	p.renderStdData()
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
}

// Drops the specified number of requests from the progress bar total.
// This may be the case when uncompleted requests are encountered and shouldn't be part of the total count.
func (p *Progress) Drop(count int64) {
	// mimic dropping by incrementing the completed requests
	p.bar.IncrInt64(count)
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

	// close the writers and wait for the EOF condition
	stopCapture(p.captureData)

	// stop the renderer and wait for it
	p.stdStopRenderEvent <- true
	p.stdRenderWaitGroup.Wait()

	// drain any stdout/stderr data
	p.drainStringBuilderTo(p.stdOut, os.Stdout)
	p.drainStringBuilderTo(p.stdErr, os.Stderr)
}

func (p *Progress) renderStdData() {
	// trigger a render event
	p.renderChan <- time.Now()

	gologger.Infof("Waiting for your terminal to settle..")
	time.Sleep(time.Millisecond * settleMilis)

	p.stdRenderWaitGroup.Add(1)

	go func(waitGroup *sync.WaitGroup) {
		for {
			select {
			case <-p.stdStopRenderEvent:
				waitGroup.Done()
				return
			case <-p.stdRenderEvent.C:
				p.stdCaptureMutex.Lock()
				{
					hasStdout := p.stdOut.Len() > 0
					hasStderr := p.stdErr.Len() > 0
					hasOutput := hasStdout || hasStderr

					if hasOutput {
						stdout := p.captureData.backupStdout
						stderr := p.captureData.backupStderr

						// go back one line and clean it all
						fmt.Fprint(stderr, "\u001b[1A\u001b[2K")
						p.drainStringBuilderTo(p.stdOut, stdout)
						p.drainStringBuilderTo(p.stdErr, stderr)

						// make space for the progressbar to render itself
						fmt.Fprintln(stderr, "")
					}

					// always trigger a render event to try ensure it's visible even with fast output
					p.renderChan <- time.Now()
				}
				p.stdCaptureMutex.Unlock()
			}
		}
	}(p.stdRenderWaitGroup)
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
