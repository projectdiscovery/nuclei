package output

import (
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

func (mw *MultiWriter) Write(event *ResultEvent) error {
	for _, writer := range mw.writers {
		if err := writer.Write(event); err != nil {
			return err
		}
	}
	return nil
}

func (mw *MultiWriter) WriteFailure(event *InternalWrappedEvent) error {
	for _, writer := range mw.writers {
		if err := writer.WriteFailure(event); err != nil {
			return err
		}
	}
	return nil
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
