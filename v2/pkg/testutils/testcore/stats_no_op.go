//go:build !stats
// +build !stats

package testcore

import (
	"context"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

type WorkpoolStats struct {
	// no-op implementation
}

func NewWorkpoolStats(ctx context.Context, size int) *WorkpoolStats {
	wp := &WorkpoolStats{}
	return wp
}

// Concurrency Safe Method to signal start of template execution
func (w *WorkpoolStats) SignalStart(template *templates.Template, target string) {}

// Concurrency Safe Method to signal end of template execution
func (w *WorkpoolStats) SignalEnd(template *templates.Template, target string) {}

// Close the stats channel
func (w *WorkpoolStats) Close() {}
