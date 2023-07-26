//go:build stats
// +build stats

package testcore

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type Stats struct {
	TemplateStart []Item `json:"template-start"`
	TemplateEnd   []Item `json:"template-end"`
	Concurrency   int    `json:"concurrency"`
}

func (s Stats) Save() error {
	if len(s.TemplateStart) == 0 && len(s.TemplateEnd) == 0 {
		return nil
	}
	filename := "stats.json"
	if val := os.Getenv("NUCLEI_STATS_FILE"); val != "" {
		filename = val
	}
	bin, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, bin, 0644)
}

type WorkpoolStats struct {
	// internal / unexported fields
	ch            chan Item
	size          int // size of the workpool
	wg            sync.WaitGroup
	templateStart []Item
	templateEnd   []Item
}

func NewWorkpoolStats(ctx context.Context, size int) *WorkpoolStats {
	wp := &WorkpoolStats{
		ch:            make(chan Item, 100),
		wg:            sync.WaitGroup{},
		templateStart: make([]Item, 0),
		templateEnd:   make([]Item, 0),
		size:          size,
	}
	wp.wg.Add(1)
	go wp.run(ctx)
	return wp
}

func (w *WorkpoolStats) run(ctx context.Context) {
	defer func() {
		s := Stats{
			TemplateStart: w.templateStart,
			TemplateEnd:   w.templateEnd,
			Concurrency:   w.size,
		}
		if err := s.Save(); err != nil {
			gologger.Info().Msgf("Could not save stats: %s\n", err)
		}
		w.wg.Done()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case Item, ok := <-w.ch:
			if !ok {
				return
			}
			switch Item.ItemType {
			case ItemStart:
				w.templateStart = append(w.templateStart, Item)
			case ItemEnd:
				w.templateEnd = append(w.templateEnd, Item)
			}
		}
	}
}

// Concurrency Safe Method to signal start of template execution
func (w *WorkpoolStats) SignalStart(template *templates.Template, target string) {
	if template == nil {
		return
	}
	item := Item{
		ID:           template.ID,
		Time:         time.Now(),
		TemplateType: getTemplateType(template),
		Target:       target,
		ItemType:     ItemStart,
		Requests:     template.Executer.Requests(),
	}
	w.ch <- item
}

// Concurrency Safe Method to signal end of template execution
func (w *WorkpoolStats) SignalEnd(template *templates.Template, target string) {
	if template == nil {
		return
	}
	item := Item{
		ID:           template.ID,
		Time:         time.Now(),
		TemplateType: getTemplateType(template),
		Target:       target,
		ItemType:     ItemEnd,
		Requests:     template.Executer.Requests(),
	}
	w.ch <- item
}

// Close the stats channel
func (w *WorkpoolStats) Close() {
	close(w.ch)
	w.wg.Wait()
}

// templateType String
func getTemplateType(template *templates.Template) string {
	if template == nil {
		return ""
	}
	if template.Type() == types.HTTPProtocol {
		if sliceutil.Contains(template.Info.Tags.ToSlice(), "oast") {
			return "oast"
		}
	}
	return template.Type().String()
}
