package progress

import (
	"github.com/vbauerster/mpb/v5"
)

// Represents a single progress bar
type Bar struct {
	bar          *mpb.Bar
	total        int64
	initialTotal int64
}

// Drops the specified number of requests from the progress bar total.
// This may be the case when uncompleted requests are encountered and shouldn't be part of the total count.
func (b *Bar) drop(count int64) {
	b.bar.IncrInt64(count)
}

// Update progress tracking information and increments the request counter by one unit.
func (b *Bar) increment() {
	b.bar.Increment()
}
