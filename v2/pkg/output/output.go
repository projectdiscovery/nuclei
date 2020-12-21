package output

import (
	"os"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
)

// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	// Close closes the output writer interface
	Close()
	// Write writes the event to file and/or screen.
	Write(Event) error
	// Request writes a log the requests trace log
	Request(templateID, url, requestType string, err error)
}

// StandardWriter is a writer writing output to file and screen for results.
type StandardWriter struct {
	json        bool
	noMetadata  bool
	aurora      aurora.Aurora
	outputFile  *fileWriter
	outputMutex *sync.Mutex
	traceFile   *fileWriter
	traceMutex  *sync.Mutex
	severityMap map[string]string
}

const (
	fgOrange  uint8  = 208
	undefined string = "undefined"
)

// Event is a single output structure from nuclei.
type Event map[string]interface{}

// NewStandardWriter creates a new output writer based on user configurations
func NewStandardWriter(colors, noMetadata, json bool, file, traceFile string) (*StandardWriter, error) {
	colorizer := aurora.NewAurora(colors)

	var outputFile *fileWriter
	if file != "" {
		output, err := newFileOutputWriter(file)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		outputFile = output
	}
	var traceOutput *fileWriter
	if traceFile != "" {
		output, err := newFileOutputWriter(traceFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not create output file")
		}
		traceOutput = output
	}
	severityMap := map[string]string{
		"info":     colorizer.Blue("info").String(),
		"low":      colorizer.Green("low").String(),
		"medium":   colorizer.Yellow("medium").String(),
		"high":     colorizer.Index(fgOrange, "high").String(),
		"critical": colorizer.Red("critical").String(),
	}
	writer := &StandardWriter{
		json:        json,
		noMetadata:  noMetadata,
		severityMap: severityMap,
		aurora:      colorizer,
		outputFile:  outputFile,
		outputMutex: &sync.Mutex{},
		traceFile:   traceOutput,
		traceMutex:  &sync.Mutex{},
	}
	return writer, nil
}

// Write writes the event to file and/or screen.
func (w *StandardWriter) Write(event Event) error {
	var data []byte
	var err error

	if w.json {
		data, err = w.formatJSON(event)
	} else {
		data, err = w.formatScreen(event)
	}
	if err != nil {
		return errors.Wrap(err, "could not format output")
	}
	_, _ = os.Stdout.Write(data)
	if w.outputFile != nil {
		if writeErr := w.outputFile.Write(data); writeErr != nil {
			return errors.Wrap(err, "could not write to output")
		}
	}
	return nil
}

// JSONTraceRequest is a trace log request written to file
type JSONTraceRequest struct {
	ID    string `json:"id"`
	URL   string `json:"url"`
	Error string `json:"error"`
	Type  string `json:"type"`
}

// Request writes a log the requests trace log
func (w *StandardWriter) Request(templateID, url, requestType string, err error) {
	if w.traceFile == nil {
		return
	}
	request := &JSONTraceRequest{
		ID:   templateID,
		URL:  url,
		Type: requestType,
	}
	if err != nil {
		request.Error = err.Error()
	} else {
		request.Error = "none"
	}

	data, err := jsoniter.Marshal(request)
	if err != nil {
		return
	}
	w.traceMutex.Lock()
	//nolint:errcheck // We don't need to do anything here
	_ = w.traceFile.Write(data)
	w.traceMutex.Unlock()
}

// Close closes the output writing interface
func (w *StandardWriter) Close() {
	if w.outputFile != nil {
		w.outputFile.Close()
	}
	if w.traceFile != nil {
		w.traceFile.Close()
	}
}
