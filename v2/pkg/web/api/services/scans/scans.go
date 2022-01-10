package scans

import (
	"context"
	"database/sql"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// ScanService is a service for controlling and launching scans
type ScanService struct {
	Logs *ErrorLogsService

	db          dbsql.Querier
	concurrency int
	cancel      context.CancelFunc
	target      *targets.TargetsStorage

	Running     *sync.Map // Map of running scan with their status
	scanRequest chan ScanRequest

	Finished chan int64
}

type RunningScan struct {
	ctx          context.Context
	cancel       context.CancelFunc
	ProgressFunc PercentReturnFunc
}

// Stop stops a running scan context
func (r *RunningScan) Stop() {
	r.cancel()
}

type ScanRequest struct {
	ScanID     int64
	ScanSource string
	Templates  []string
	Targets    []string
	Config     string
	RunNow     bool
	Reporting  string
}

// NewScanService returns a new scan service
func NewScanService(logs string, concurrency int, db dbsql.Querier, target *targets.TargetsStorage) *ScanService {
	context, cancel := context.WithCancel(context.Background())

	// Do not use cache as the template contents depend upon db
	templates.NoCacheUsage = true
	parsers.NoCacheUsage = true

	// Use the db based loader
	generators.DefaultLoader = &dbPayloadLoader{db: db}
	service := &ScanService{
		Logs:        NewErrorLogsService(logs),
		db:          db,
		concurrency: concurrency,
		cancel:      cancel,
		target:      target,
		Running:     &sync.Map{},
		scanRequest: make(chan ScanRequest),
		Finished:    make(chan int64),
	}
	for i := 0; i < concurrency; i++ {
		go func() {
			for {
				select {
				case req := <-service.scanRequest:
					if err := service.worker(req); err != nil {
						log.Printf("Could not run worker: %s (%d)\n", err, req.ScanID)
					}
					service.Finished <- req.ScanID
				case <-context.Done():
					return
				}
			}
		}()
	}
	go service.pollDB(context)
	return service
}

func (s *ScanService) Close() {
	s.cancel()
	s.Logs.Close()
	close(s.Finished)
}

// Queue queues a scan request to the service
func (s *ScanService) Queue(req ScanRequest) {
	s.scanRequest <- req
}

// Progress returns the progress map for all scan ids
func (s *ScanService) Progress() map[int64]float64 {
	values := make(map[int64]float64)
	s.Running.Range(func(key interface{}, value interface{}) bool {
		keyValue := key.(int64)
		valueFunc := value.(*RunningScan)
		values[keyValue] = valueFunc.ProgressFunc()
		return true
	})
	return values
}

// pollDB polls db for schedule scans and runs them
func (s *ScanService) pollDB(ctx context.Context) {
	scheduler := gocron.NewScheduler(time.UTC)

	// We have three types of scheduled tasks - daily, weekly, monthly
	// which can be scheduled at any specified time.
	scheduler.Every(1).Day().Do(func() {
		s.queueScansForSchedule("daily")
	})
	scheduler.Every(1).Week().Do(func() {
		s.queueScansForSchedule("weekly")
	})
	scheduler.Every(1).Month().Do(func() {
		s.queueScansForSchedule("monthly")
	})
	scheduler.StartAsync()

	for range ctx.Done() {
		scheduler.Stop()
		break
	}
}

// queueScansForSchedule takes a schedule and queues scans based on that
func (s *ScanService) queueScansForSchedule(schedule string) {
	scans, err := s.db.GetScansForSchedule(context.Background(), sql.NullString{String: schedule, Valid: true})
	if err != nil {
		return
	}
	for _, scan := range scans {
		s.Queue(ScanRequest{
			ScanID:     scan.ID,
			ScanSource: scan.Scansource,
			Templates:  scan.Templates,
			Targets:    scan.Targets,
			Config:     scan.Config.String,
			Reporting:  scan.Reporting.String,
		})
	}
}

// CalculateTargetCount calculates target count from Target ID (int) or static targets.
func CalculateTargetCount(targets []string, db dbsql.Querier) int64 {
	var targetCount int64

	for _, target := range targets {
		targetID, err := strconv.ParseInt(target, 10, 64)
		if err != nil {
			targetCount++
		} else {
			resp, _ := db.GetTarget(context.Background(), targetID)
			targetCount += resp.Total
		}
	}
	return targetCount
}
