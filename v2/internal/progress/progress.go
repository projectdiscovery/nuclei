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
	bars            map[string]*Bar
	gbar            *Bar
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
		stdCaptureMutex: &sync.Mutex{},
		stdout:          &strings.Builder{},
		stderr:          &strings.Builder{},
		colorizer:       aurora.NewAurora(!noColor),
		bars:            make(map[string]*Bar),
	}
	return p
}

// Creates and returns a progress bar that tracks request progress for a specific template.
func (p *Progress) SetupTemplateProgressbar(templateId string, requestCount int64, priority int) {
	if p.bars[templateId] != nil {
		panic(fmt.Sprintf("A progressbar is already bound to [%s].", templateId))
	}

	color := p.colorizer
	uiBarName := templateId

	const MaxLen = 40
	if len(uiBarName) > MaxLen {
		uiBarName = uiBarName[:MaxLen] + ".."
	}

	barName := color.BrightYellow(uiBarName).String()
	bar := p.setupProgressbar(barName, requestCount, priority)

	p.bars[templateId] = &Bar{
		bar:          bar,
		total:        requestCount,
		initialTotal: requestCount,
	}
}

func pluralize(count int64, singular, plural string) string {
	if count > 1 {
		return plural
	}
	return singular
}

// Creates and returns a progress bar that tracks all the requests progress.
// This is only useful when multiple templates are processed within the same run.
func (p *Progress) SetupGlobalProgressbar(hostCount int64, templateCount int, requestCount int64) {
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

	bar := p.setupProgressbar(barName, requestCount, 0)

	p.gbar = &Bar{
		bar:          bar,
		total:        requestCount,
		initialTotal: requestCount,
	}
}

// Update progress tracking information and increments the request counter by one unit.
// If a global progress bar is present it will be updated as well.
func (p *Progress) Update(templateId string) {
	p.bars[templateId].increment()
	if p.gbar != nil {
		p.gbar.increment()
	}
}

// Drops the specified number of requests from the progress bar total.
// This may be the case when uncompleted requests are encountered and shouldn't be part of the total count.
// If a global progress bar is present it will be updated as well.
func (p *Progress) Drop(templateId string, count int64) {
	p.bars[templateId].drop(count)
	if p.gbar != nil {
		p.gbar.drop(count)
	}
}

// Ensures that a progress bar's total count is up-to-date if during an enumeration there were uncompleted requests and
// wait for all the progress bars to finish.
// If a global progress bar is present it will be updated as well.
func (p *Progress) Wait() {
	p.progress.Wait()
}

// Creates and returns a progress bar.
func (p *Progress) setupProgressbar(name string, total int64, priority int) *mpb.Bar {
	color := p.colorizer

	return p.progress.AddBar(
		total,
		mpb.BarPriority(priority),
		mpb.BarNoPop(),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(fmt.Sprintf("[%s]", name), decor.WCSyncSpaceR),
			decor.CountersNoUnit(color.BrightBlue(" %d/%d").String(), decor.WCSyncSpace),
			decor.NewPercentage(color.Bold("%d").String(), decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.AverageSpeed(0, color.BrightBlue("%.2f r/s ").String(), decor.WCSyncSpace),
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
