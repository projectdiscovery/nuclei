package output

import (
	"sync"

	"github.com/logrusorgru/aurora"
)

type MultiWriter struct {
	writers []Writer
}

var _ Writer = &MultiWriter{}

// NewMultiWriter creates a new MultiWriter instance
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (mw *MultiWriter) Close() {
	for _, writer := range mw.writers {
		writer.Close()
	}
}

func (mw *MultiWriter) Colorizer() aurora.Aurora {
	// Return the colorizer of the first writer
	if len(mw.writers) > 0 {
		return mw.writers[0].Colorizer()
	}
	// Default to a no-op colorizer
	return aurora.NewAurora(false)
}

// Write fans out the event to all underlying writers concurrently. The local
// file/stdout writer typically completes in microseconds while remote writers
// (e.g. PDCP upload) can take hundreds of milliseconds; running them serially
// gates the fast path on the slowest writer. With concurrent fan-out the
// caller waits at most max(writer latencies) instead of sum.
//
// Behavior change vs. previous implementation: errors no longer short-circuit
// the remaining writers. All writers are attempted; the first observed error
// is returned. This is intentional: a transient PDCP upload failure should
// not silently drop the local file/json result.
func (mw *MultiWriter) Write(event *ResultEvent) error {
	if len(mw.writers) == 1 {
		return mw.writers[0].Write(event)
	}
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	wg.Add(len(mw.writers))
	for _, w := range mw.writers {
		go func(w Writer) {
			defer wg.Done()
			if err := w.Write(event); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return firstErr
}

// WriteFailure mirrors Write semantics: fan-out and collect the first error.
func (mw *MultiWriter) WriteFailure(event *InternalWrappedEvent) error {
	if len(mw.writers) == 1 {
		return mw.writers[0].WriteFailure(event)
	}
	var (
		mu       sync.Mutex
		firstErr error
		wg       sync.WaitGroup
	)
	wg.Add(len(mw.writers))
	for _, w := range mw.writers {
		go func(w Writer) {
			defer wg.Done()
			if err := w.WriteFailure(event); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	return firstErr
}

func (mw *MultiWriter) Request(templateID, url, requestType string, err error) {
	for _, writer := range mw.writers {
		writer.Request(templateID, url, requestType, err)
	}
}

func (mw *MultiWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {
	for _, writer := range mw.writers {
		writer.WriteStoreDebugData(host, templateID, eventType, data)
	}
}

func (mw *MultiWriter) RequestStatsLog(statusCode, response string) {
	for _, writer := range mw.writers {
		writer.RequestStatsLog(statusCode, response)
	}
}

func (mw *MultiWriter) ResultCount() int {
	count := 0
	for _, writer := range mw.writers {
		if count := writer.ResultCount(); count > 0 {
			return count
		}
	}
	return count
}
