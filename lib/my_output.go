package nuclei

import (
	"github.com/logrusorgru/aurora"
	"github.com/secoba/nuclei/v3/pkg/output"
	"sync"
)

type MyWriter struct {
	resultEvents  []*output.ResultEvent
	failureEvents []*output.InternalWrappedEvent
	mutex         sync.RWMutex
}

// Close closes the output writer interface
func (w *MyWriter) Close() {}

// Colorizer returns the colorizer instance for writer
func (w *MyWriter) Colorizer() aurora.Aurora {
	return aurora.NewAurora(false)
}

// Write writes the event to file and/or screen.
func (w *MyWriter) Write(event *output.ResultEvent) error {
	w.mutex.Lock()
	if w.resultEvents == nil {
		w.resultEvents = []*output.ResultEvent{}
	}
	w.resultEvents = append(w.resultEvents, event)
	w.mutex.Unlock()
	return nil
}

// WriteFailure writes the optional failure event for template to file and/or screen.
func (w *MyWriter) WriteFailure(event *output.InternalWrappedEvent) error {
	w.mutex.Lock()
	if w.failureEvents == nil {
		w.failureEvents = []*output.InternalWrappedEvent{}
	}
	w.failureEvents = append(w.failureEvents, event)
	w.mutex.Unlock()
	return nil
}

// Request logs a request in the trace log
func (w *MyWriter) Request(templateID, url, requestType string, err error) {}

func (w *MyWriter) GetFailures() []*output.InternalWrappedEvent {
	return w.failureEvents
}

func (w *MyWriter) GetResults() []*output.ResultEvent {
	return w.resultEvents
}

func (w *MyWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}
