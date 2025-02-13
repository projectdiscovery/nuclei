package output

import (
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/output/stats"
)

// StatsOutputWriter implements writer interface for stats observation
type StatsOutputWriter struct {
	colorizer aurora.Aurora
	Tracker   *stats.Tracker
}

var _ Writer = &StatsOutputWriter{}

// NewStatsOutputWriter returns a new StatsOutputWriter instance.
func NewTrackerWriter(t *stats.Tracker) *StatsOutputWriter {
	return &StatsOutputWriter{
		colorizer: aurora.NewAurora(true),
		Tracker:   t,
	}
}

func (tw *StatsOutputWriter) Close() {}

func (tw *StatsOutputWriter) Colorizer() aurora.Aurora {
	return tw.colorizer
}

func (tw *StatsOutputWriter) Write(event *ResultEvent) error {
	return nil
}

func (tw *StatsOutputWriter) WriteFailure(event *InternalWrappedEvent) error {
	return nil
}

func (tw *StatsOutputWriter) Request(templateID, url, requestType string, err error) {
	if err == nil {
		return
	}
	jsonReq := getJSONLogRequestFromError(templateID, url, requestType, err)
	tw.Tracker.TrackErrorKind(jsonReq.Error)
}

func (tw *StatsOutputWriter) WriteStoreDebugData(host, templateID, eventType string, data string) {}

func (tw *StatsOutputWriter) RequestStatsLog(statusCode, response string) {
	tw.Tracker.TrackStatusCode(statusCode)
	tw.Tracker.TrackWAFDetected(response)
}
