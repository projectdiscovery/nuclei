package charts

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/labstack/echo/v4"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan/events"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	fileutil "github.com/projectdiscovery/utils/file"
)

// ScanEventsCharts is a struct for nuclei event charts
type ScanEventsCharts struct {
	eventsDir string
	config    *events.ScanConfig
	data      []events.ScanEvent
}

func (sc *ScanEventsCharts) PrintInfo() {
	fmt.Printf("[+] Scan Info\n")
	fmt.Printf("  - Name: %s\n", sc.config.Name)
	fmt.Printf("  - Target Count: %d\n", sc.config.TargetCount)
	fmt.Printf("  - Template Count: %d\n", sc.config.TemplatesCount)
	fmt.Printf("  - Template Concurrency: %d\n", sc.config.TemplateConcurrency)
	fmt.Printf("  - Payload Concurrency: %d\n", sc.config.PayloadConcurrency)
	fmt.Printf("  - Retries: %v\n", sc.config.Retries)
	fmt.Printf("  - Total Events: %d\n", len(sc.data))
	fmt.Println()
}

// NewScanEventsCharts creates a new nuclei event charts
func NewScanEventsCharts(eventsDir string) (*ScanEventsCharts, error) {
	sc := &ScanEventsCharts{eventsDir: eventsDir}
	if !fileutil.FolderExists(eventsDir) {
		return nil, fmt.Errorf("events directory does not exist")
	}
	// open two files
	// config.json
	bin, err := os.ReadFile(filepath.Join(eventsDir, events.ConfigFile))
	if err != nil {
		return nil, err
	}
	var config events.ScanConfig
	err = json.Unmarshal(bin, &config)
	if err != nil {
		return nil, err
	}
	sc.config = &config

	// events.jsonl
	f, err := os.Open(filepath.Join(eventsDir, events.EventsFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := []events.ScanEvent{}
	dec := json.NewDecoder(f)
	for {
		var event events.ScanEvent
		if err := dec.Decode(&event); err != nil {
			break
		}
		data = append(data, event)
	}
	sc.data = data

	if len(data) == 0 {
		return nil, fmt.Errorf("no events found in the events file")
	}

	return sc, nil
}

// Start starts the nuclei event charts server
func (sc *ScanEventsCharts) Start(addr string) {
	e := echo.New()
	e.HideBanner = true
	e.GET("/concurrency", sc.ConcurrencyVsTime)
	e.GET("/fuzz", sc.TotalRequestsOverTime)
	e.GET("/slow", sc.TopSlowTemplates)
	e.GET("/rps", sc.RequestsVSInterval)
	e.GET("/", sc.AllCharts)
	e.Logger.Fatal(e.Start(addr))
}
