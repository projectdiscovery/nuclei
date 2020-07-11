package progress

import (
	"github.com/vbauerster/mpb/v5"
	"sync/atomic"
)

// Represents a single progress bar
type Bar struct {
	bar          *mpb.Bar
	total        int64
	initialTotal int64
}

// Drops the specified number of requests from the progress bar total.
// This may be the case when uncompleted requests are encountered and shouldn't be part of the total count.
func (b *Bar) Drop(count int64) {
	atomic.AddInt64(&b.total, -count)
	b.bar.SetTotal(atomic.LoadInt64(&b.total), false)
}

// Ensures that a progress bar's total count is up-to-date if during an enumeration there were uncompleted requests.
func (b *Bar) finish() {
	if b.initialTotal != b.total {
		b.bar.SetTotal(b.total, true)
	}
}
