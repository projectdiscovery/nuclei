package charts

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan/events"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

const (
	TopK         = 50
	SpacerHeight = "50px"
)

func (s *ScanEventsCharts) AllCharts(c echo.Context) error {
	page := s.allCharts(c)
	return page.Render(c.Response().Writer)
}

func (s *ScanEventsCharts) GenerateHTML(filePath string) error {
	page := s.allCharts(nil)
	output, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer output.Close()
	return page.Render(output)
}

// AllCharts generates all the charts for the scan events and returns a page component
func (s *ScanEventsCharts) allCharts(c echo.Context) *components.Page {
	page := components.NewPage()
	page.PageTitle = "Nuclei Charts"
	line1 := s.totalRequestsOverTime(c)
	// line1.SetSpacerHeight(SpacerHeight)
	kline := s.topSlowTemplates(c)
	// kline.SetSpacerHeight(SpacerHeight)
	line2 := s.requestsVSInterval(c)
	// line2.SetSpacerHeight(SpacerHeight)
	line3 := s.concurrencyVsTime(c)
	// line3.SetSpacerHeight(SpacerHeight)
	page.AddCharts(line1, kline, line2, line3)
	page.SetLayout(components.PageCenterLayout)
	page.Theme = "dark"
	page.Validate()

	return page
}

func (s *ScanEventsCharts) TotalRequestsOverTime(c echo.Context) error {
	line := s.totalRequestsOverTime(c)
	return line.Render(c.Response().Writer)
}

// totalRequestsOverTime generates a line chart showing total requests count over time
func (s *ScanEventsCharts) totalRequestsOverTime(c echo.Context) *charts.Line {
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title:    "Nuclei: Total Requests vs Time",
			Subtitle: "Chart Shows Total Requests Count Over Time (for each/all Protocols)",
		}),
	)

	var startTime time.Time = time.Now()
	var endTime time.Time

	for _, event := range s.data {
		if event.Time.Before(startTime) {
			startTime = event.Time
		}
		if event.Time.After(endTime) {
			endTime = event.Time
		}
	}
	data := getCategoryRequestCount(s.data)
	max := 0
	for _, v := range data {
		if len(v) > max {
			max = len(v)
		}
	}
	line.SetXAxis(time.Now().Format(time.RFC3339))
	for k, v := range data {
		lineData := make([]opts.LineData, 0)
		temp := 0
		for _, scanEvent := range v {
			temp += scanEvent.MaxRequests
			val := scanEvent.Time.Sub(startTime)
			lineData = append(lineData, opts.LineData{
				Value: []interface{}{val.Milliseconds(), temp},
				Name:  scanEvent.TemplateID,
			})
		}
		line.AddSeries(k, lineData, charts.WithLineChartOpts(opts.LineChart{Smooth: false}), charts.WithLabelOpts(opts.Label{Show: true, Position: "top"}))
	}

	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: "Nuclei: total-req vs time"}),
		charts.WithXAxisOpts(opts.XAxis{Name: "Time", Type: "time", AxisLabel: &opts.AxisLabel{Show: true, ShowMaxLabel: true, Formatter: opts.FuncOpts(`function (date) { return (date/1000)+'s'; }`)}}),
		charts.WithYAxisOpts(opts.YAxis{Name: "Requests Sent", Type: "value"}),
		charts.WithInitializationOpts(opts.Initialization{Theme: "dark"}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "slider", Start: 0, End: 100}),
		charts.WithGridOpts(opts.Grid{Left: "10%", Right: "10%", Bottom: "15%", Top: "20%"}),
		charts.WithToolboxOpts(opts.Toolbox{Show: true, Feature: &opts.ToolBoxFeature{
			SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: true, Name: "save", Title: "save"},
			DataZoom:    &opts.ToolBoxFeatureDataZoom{Show: true, Title: map[string]string{"zoom": "zoom", "back": "back"}},
			DataView:    &opts.ToolBoxFeatureDataView{Show: true, Title: "raw", Lang: []string{"raw", "exit", "refresh"}},
		}}),
	)

	line.Validate()
	return line
}

func (s *ScanEventsCharts) TopSlowTemplates(c echo.Context) error {
	kline := s.topSlowTemplates(c)
	return kline.Render(c.Response().Writer)
}

// topSlowTemplates generates a Kline chart showing the top slow templates by time taken
func (s *ScanEventsCharts) topSlowTemplates(c echo.Context) *charts.Kline {
	kline := charts.NewKLine()
	kline.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title:    "Nuclei: Top Slow Templates",
			Subtitle: fmt.Sprintf("Chart Shows Top Slow Templates (by time taken) (Top %v)", TopK),
		}),
	)
	ids := map[string][]int64{}
	var startTime time.Time = time.Now()
	for _, event := range s.data {
		if event.Time.Before(startTime) {
			startTime = event.Time
		}
	}
	for _, event := range s.data {
		ids[event.TemplateID] = append(ids[event.TemplateID], event.Time.Sub(startTime).Milliseconds())
	}

	type entry struct {
		ID        string
		KlineData opts.KlineData
		start     int64
		end       int64
	}
	data := []entry{}

	for a, b := range ids {
		if len(b) < 2 {
			continue // Prevents index out of range error
		}
		d := entry{
			ID:        a,
			KlineData: opts.KlineData{Value: []int64{b[0], b[len(b)-1], b[0], b[len(b)-1]}}, // Adjusted to prevent index out of range error
			start:     b[0],
			end:       b[len(b)-1],
		}
		data = append(data, d)
	}

	sort.Slice(data, func(i, j int) bool {
		return data[i].end-data[i].start > data[j].end-data[j].start
	})

	x := make([]string, 0)
	y := make([]opts.KlineData, 0)
	for _, event := range data[:TopK] {
		x = append(x, event.ID)
		y = append(y, event.KlineData)
	}

	kline.SetXAxis(x).AddSeries("templates", y)
	kline.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: fmt.Sprintf("Nuclei: Top %v Slow Templates", TopK)}),
		charts.WithXAxisOpts(opts.XAxis{
			Type:      "category",
			Show:      true,
			AxisLabel: &opts.AxisLabel{Rotate: 90, Show: true, ShowMinLabel: true, ShowMaxLabel: true, Formatter: opts.FuncOpts(`function (value) { return value; }`)},
		}),
		charts.WithYAxisOpts(opts.YAxis{
			Scale:     true,
			Type:      "value",
			Show:      true,
			AxisLabel: &opts.AxisLabel{Show: true, Formatter: opts.FuncOpts(`function (ms) {  return Math.floor(ms/60000) + 'm' + Math.floor((ms/60000 - Math.floor(ms/60000))*60) + 's'; }`)},
		}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "slider", Start: 0, End: 100}),
		charts.WithGridOpts(opts.Grid{Left: "10%", Right: "10%", Bottom: "40%", Top: "10%"}),
		charts.WithTooltipOpts(opts.Tooltip{Show: true, Trigger: "events.ScanEvent", TriggerOn: "mousemove|click", Enterable: true, Formatter: opts.FuncOpts(`function (params) { return params.name ; }`)}),
		charts.WithToolboxOpts(opts.Toolbox{Show: true, Feature: &opts.ToolBoxFeature{
			SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: true, Name: "save", Title: "save"},
			DataZoom:    &opts.ToolBoxFeatureDataZoom{Show: true, Title: map[string]string{"zoom": "zoom", "back": "back"}},
			DataView:    &opts.ToolBoxFeatureDataView{Show: true, Title: "raw", Lang: []string{"raw", "exit", "refresh"}},
		}}),
	)

	return kline
}

func (s *ScanEventsCharts) RequestsVSInterval(c echo.Context) error {
	line := s.requestsVSInterval(c)
	return line.Render(c.Response().Writer)
}

// requestsVSInterval generates a line chart showing requests per second over time
func (s *ScanEventsCharts) requestsVSInterval(c echo.Context) *charts.Line {
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title:    "Nuclei: Requests Per Second vs Time",
			Subtitle: "Chart Shows RPS (Requests Per Second) Over Time",
		}),
	)

	sort.Slice(s.data, func(i, j int) bool {
		return s.data[i].Time.Before(s.data[j].Time)
	})

	var interval time.Duration

	if c != nil {
		interval, _ = time.ParseDuration(c.QueryParam("interval"))
	}
	if interval <= 3 {
		interval = 5 * time.Second
	}

	data := []opts.LineData{}
	temp := 0
	if len(s.data) > 0 {
		orig := s.data[0].Time
		startTime := orig
		xaxisData := []int64{}
		for _, v := range s.data {
			if v.Time.Sub(startTime) > interval {
				millisec := v.Time.Sub(orig).Milliseconds()
				xaxisData = append(xaxisData, millisec)
				data = append(data, opts.LineData{Value: temp, Name: v.Time.Sub(orig).String()})
				temp = 0
				startTime = v.Time
			}
			temp += 1
		}
		// Handle last interval if exists
		if temp > 0 {
			millisec := s.data[len(s.data)-1].Time.Sub(orig).Milliseconds()
			xaxisData = append(xaxisData, millisec)
			data = append(data, opts.LineData{Value: temp, Name: s.data[len(s.data)-1].Time.Sub(orig).String()})
		}
		line.SetXAxis(xaxisData)
		line.AddSeries("RPS", data, charts.WithLineChartOpts(opts.LineChart{Smooth: false}), charts.WithLabelOpts(opts.Label{Show: true, Position: "top"}))
	}

	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: "Nuclei: Template Execution", Subtitle: "Time Interval: " + interval.String()}),
		charts.WithXAxisOpts(opts.XAxis{Name: "Time Intervals", Type: "category", AxisLabel: &opts.AxisLabel{Show: true, ShowMaxLabel: true, Formatter: opts.FuncOpts(`function (date) { return (date/1000)+'s'; }`)}}),
		charts.WithYAxisOpts(opts.YAxis{Name: "RPS Value", Type: "value", Show: true}),
		charts.WithInitializationOpts(opts.Initialization{Theme: "dark"}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "slider", Start: 0, End: 100}),
		charts.WithGridOpts(opts.Grid{Left: "10%", Right: "10%", Bottom: "15%", Top: "20%"}),
		charts.WithToolboxOpts(opts.Toolbox{Show: true, Feature: &opts.ToolBoxFeature{
			SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: true, Name: "save", Title: "save"},
			DataZoom:    &opts.ToolBoxFeatureDataZoom{Show: true, Title: map[string]string{"zoom": "zoom", "back": "back"}},
			DataView:    &opts.ToolBoxFeatureDataView{Show: true, Title: "raw", Lang: []string{"raw", "exit", "refresh"}},
		}}),
	)

	line.Validate()
	return line
}

func (s *ScanEventsCharts) ConcurrencyVsTime(c echo.Context) error {
	line := s.concurrencyVsTime(c)
	return line.Render(c.Response().Writer)
}

// concurrencyVsTime generates a line chart showing concurrency (total workers) over time
func (s *ScanEventsCharts) concurrencyVsTime(c echo.Context) *charts.Line {
	line := charts.NewLine()
	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{
			Title:    "Nuclei: Concurrency vs Time",
			Subtitle: "Chart Shows Concurrency (Total Workers) Over Time",
		}),
	)

	dataset := sliceutil.Clone(s.data)

	sort.Slice(dataset, func(i, j int) bool {
		return dataset[i].Time.Before(dataset[j].Time)
	})

	var interval time.Duration
	if c != nil {
		interval, _ = time.ParseDuration(c.QueryParam("interval"))
	}
	if interval <= 3 {
		interval = 5 * time.Second
	}

	// create array with time interval as x-axis and worker count as y-axis
	// entry is a struct with time and poolsize
	type entry struct {
		Time     time.Duration
		poolsize int
	}
	allEntries := []entry{}

	dataIndex := 0
	maxIndex := len(dataset) - 1
	currEntry := entry{}

	lastTime := dataset[0].Time
	for dataIndex <= maxIndex {
		currTime := dataset[dataIndex].Time
		if currTime.Sub(lastTime) > interval {
			// next batch
			currEntry.Time = interval
			allEntries = append(allEntries, currEntry)
			lastTime = dataset[dataIndex-1].Time
		}
		if dataset[dataIndex].EventType == events.ScanStarted {
			currEntry.poolsize += 1
		} else {
			currEntry.poolsize -= 1
		}
		dataIndex += 1
	}

	plotData := []opts.LineData{}
	xaxisData := []int64{}
	tempTime := time.Duration(0)
	for _, v := range allEntries {
		tempTime += v.Time
		plotData = append(plotData, opts.LineData{Value: v.poolsize, Name: tempTime.String()})
		xaxisData = append(xaxisData, tempTime.Milliseconds())
	}
	line.SetXAxis(xaxisData)
	line.AddSeries("Concurrency", plotData, charts.WithLineChartOpts(opts.LineChart{Smooth: false}), charts.WithLabelOpts(opts.Label{Show: true, Position: "top"}))

	line.SetGlobalOptions(
		charts.WithTitleOpts(opts.Title{Title: "Nuclei: WorkerPool", Subtitle: "Time Interval: " + interval.String()}),
		charts.WithXAxisOpts(opts.XAxis{Name: "Time Intervals", Type: "category", AxisLabel: &opts.AxisLabel{Show: true, ShowMaxLabel: true, Formatter: opts.FuncOpts(`function (date) { return (date/1000)+'s'; }`)}}),
		charts.WithYAxisOpts(opts.YAxis{Name: "Total Workers", Type: "value", Show: true}),
		charts.WithInitializationOpts(opts.Initialization{Theme: "dark"}),
		charts.WithDataZoomOpts(opts.DataZoom{Type: "slider", Start: 0, End: 100}),
		charts.WithGridOpts(opts.Grid{Left: "10%", Right: "10%", Bottom: "15%", Top: "20%"}),
		charts.WithToolboxOpts(opts.Toolbox{Show: true, Feature: &opts.ToolBoxFeature{
			SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{Show: true, Name: "save", Title: "save"},
			DataZoom:    &opts.ToolBoxFeatureDataZoom{Show: true, Title: map[string]string{"zoom": "zoom", "back": "back"}},
			DataView:    &opts.ToolBoxFeatureDataView{Show: true, Title: "raw", Lang: []string{"raw", "exit", "refresh"}},
		}}),
	)

	line.Validate()
	return line
}

// getCategoryRequestCount returns a map of category and request count
func getCategoryRequestCount(values []events.ScanEvent) map[string][]events.ScanEvent {
	mx := make(map[string][]events.ScanEvent)
	for _, event := range values {
		mx[event.TemplateType] = append(mx[event.TemplateType], event)
	}
	return mx
}
