package scans

import (
	"context"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/web/api/services/targets"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
)

// ScanService is a service for controlling and launching scans
type ScanService struct {
	Logs *ErrorLogsService

	db          *db.Database
	concurrency int
	cancel      context.CancelFunc
	target      *targets.TargetsStorage

	running     *sync.Map // Map of running scan with their status
	scanRequest chan ScanRequest
}

type ScanRequest struct {
	ScanID    int64
	Templates []string
	Targets   []string
	Config    string
	RunNow    bool
	Reporting string
}

// NewScanService returns a new scan service
func NewScanService(logs string, concurrency int, db *db.Database, target *targets.TargetsStorage) *ScanService {
	context, cancel := context.WithCancel(context.Background())

	service := &ScanService{
		Logs:        NewErrorLogsService(logs),
		db:          db,
		concurrency: concurrency,
		cancel:      cancel,
		target:      target,
		running:     &sync.Map{},
		scanRequest: make(chan ScanRequest),
	}
	for i := 0; i < concurrency; i++ {
		go func() {
			for {
				select {
				case req := <-service.scanRequest:
					if err := service.worker(req); err != nil {
						log.Printf("Could not run worker: %s (%d)\n", err, req.ScanID)
					}
				case <-context.Done():
					return
				}
			}
		}()
	}
	return service
}

func (s *ScanService) Close() {
	s.cancel()
}

// Queue queues a scan request to the service
func (s *ScanService) Queue(req ScanRequest) {
	s.scanRequest <- req
}

// Progress returns the progress map for all scan ids
func (s *ScanService) Progress() map[int64]float64 {
	values := make(map[int64]float64)
	s.running.Range(func(key interface{}, value interface{}) bool {
		keyValue := key.(int64)
		valueFunc := value.(percentReturnFunc)
		values[keyValue] = valueFunc()
		return true
	})
	return values
}

func (s *ScanService) pollDB(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		if ctx.Err() != nil {
			return
		}
		// todo: schedule tasks based on time here.
	}
}

// CalculateTargetCount calculates target count from Target ID (int) or static targets.
func CalculateTargetCount(targets []string, db *db.Database) int64 {
	var targetCount int64

	for _, target := range targets {
		targetID, err := strconv.ParseInt(target, 10, 64)
		if err != nil {
			targetCount++
		} else {
			resp, _ := db.Queries().GetTarget(context.Background(), targetID)
			targetCount += resp.Total.Int64
		}
	}
	return targetCount
}
