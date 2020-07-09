package progress

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/cwriter"
	"github.com/vbauerster/mpb/v5/decor"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

type Progress struct {
	progress        *mpb.Progress
	bar             *mpb.Bar
	total           int64
	initialTotal    int64
	captureData     *captureData
	termWidth       int
	stdCaptureMutex *sync.Mutex
	stdout          *strings.Builder
	stderr          *strings.Builder
}

func NewProgress(group *sync.WaitGroup) *Progress {
	w := cwriter.New(os.Stderr)
	tw, err := w.GetWidth()
	if err != nil {
		tw = 80
	}

	p := &Progress{
		progress: mpb.New(
			mpb.WithWaitGroup(group),
			mpb.WithOutput(os.Stderr),
			mpb.PopCompletedMode(),
		),
		termWidth:       tw,
		stdCaptureMutex: &sync.Mutex{},
		stdout:          &strings.Builder{},
		stderr:          &strings.Builder{},
	}
	return p
}

func (p *Progress) SetupProgressBar(name string, total int64) *mpb.Bar {
	barname := "[" + aurora.Green(name).String() + "]"
	bar := p.progress.AddBar(
		total,
		mpb.BarNoPop(),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(barname),
			decor.CountersNoUnit(aurora.Blue(" %d/%d").String()),
			decor.NewPercentage(aurora.Bold("%d").String(), decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.AverageSpeed(0, aurora.Yellow("%.2f req/s ").String()),
			decor.OnComplete(
				decor.AverageETA(decor.ET_STYLE_GO), aurora.Bold("done!").String(),
			),
		),
	)

	p.bar = bar
	p.total = total
	p.initialTotal = total
	return bar
}

func (p *Progress) Update() {
	p.bar.Increment()
}

func (p *Progress) Abort(remaining int64) {
	atomic.AddInt64(&p.total, -remaining)
	p.bar.SetTotal(atomic.LoadInt64(&p.total), false)
}

func (p *Progress) Wait() {
	if p.initialTotal != p.total {
		p.bar.SetTotal(p.total, true)
	}
	p.progress.Wait()
}

//

func (p *Progress) StartStdCapture() {
	p.stdCaptureMutex.Lock()
	p.captureData = startStdCapture()
}

func (p *Progress) StopStdCapture() {
	stopStdCapture(p.captureData)
	p.stdout.Write(p.captureData.DataStdOut.Bytes())
	p.stderr.Write(p.captureData.DataStdErr.Bytes())
	p.stdCaptureMutex.Unlock()
}

func (p *Progress) ShowStdOut() {
	if p.stdout.Len() > 0 {
		fmt.Fprint(os.Stdout, p.stdout.String())
	}
}

func (p *Progress) ShowStdErr() {
	if p.stderr.Len() > 0 {
		fmt.Fprint(os.Stderr, p.stderr.String())
	}
}
