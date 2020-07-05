package progress

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/vbauerster/mpb/v5"
	"github.com/vbauerster/mpb/v5/cwriter"
	"github.com/vbauerster/mpb/v5/decor"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type Progress struct {
	progress *mpb.Progress
	Bar *mpb.Bar
	captureData *captureData
	termWidth int
}

func NewProgress(group *sync.WaitGroup) *Progress {
	w := cwriter.New(os.Stdout)
	tw, err := w.GetWidth()
	if err != nil {
		panic("Couldn't determine available terminal width.")
	}

	p := &Progress{
		progress: mpb.New(
			mpb.WithWaitGroup(group),
			mpb.WithOutput(os.Stderr),
			mpb.PopCompletedMode(),
		),
		termWidth: tw,
		Bar: nil,
	}
	return p
}

func (p *Progress) NewBar(name string, total int64) *mpb.Bar {
	barname := "[" + aurora.Green(name).String() + "]"

	return p.progress.AddBar(
		total,
		mpb.BarNoPop(),
		//mpb.BarQueueAfter(p.Bar),
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(barname),
			decor.CountersNoUnit(aurora.Blue(" %d/%d").String()),
			decor.NewPercentage(aurora.Bold("%d").String(), decor.WCSyncSpace),
		),
		mpb.AppendDecorators(
			decor.EwmaSpeed(0, aurora.Yellow("%.2f req/s ").String(), 60),
			decor.OnComplete(
				decor.EwmaETA(decor.ET_STYLE_GO, 60), aurora.Bold("done!").String(),
			),
		),
	)
}

func (p *Progress) Wait() {
	p.progress.Wait()
}

//

func (p *Progress) StartStdCapture() {
	p.captureData = startStdCapture()
}

func (p *Progress) StopStdCaptureAndShow() {
	stopStdCapture(p.captureData)
	for _, captured := range p.captureData.Data {
		var r = regexp.MustCompile("(.{" + strconv.Itoa(p.termWidth) + "})")
		multiline := r.ReplaceAllString(captured, "$1\n")
		arr := strings.Split(multiline, "\n")

		for _, msg := range arr {
			p.progress.Add(0, makeLogBar(msg)).SetTotal(0, true)
		}
	}
}

func makeLogBar(msg string) mpb.BarFiller {
	return mpb.BarFillerFunc(func(w io.Writer, _ int, st decor.Statistics) {
		fmt.Fprintf(w, msg)
	})
}
