// Package monitor implements a goroutine based monitoring for
// detecting stuck scanner processes and dumping stack and other
// relevant information for investigation.
//
// To use, just import as below -
//   import _ "github.com/projectdiscovery/nuclei/v2/utils/monitor"
package monitor

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/rs/xid"
)

// Agent is an agent for monitoring hanging programs
type Agent struct {
	cancel context.CancelFunc

	goroutineCount   int
	currentIteration int // number of times we've checked hang
}

const defaultMonitorIteration = 5

// NewStackMonitor returns a new stack monitor instance
func NewStackMonitor(interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(interval)

	monitor := &Agent{cancel: cancel}
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
			case <-ticker.C:
				monitor.monitorWorker()
			default:
				continue
			}
		}
	}()
	return cancel
}

// monitorWorker is a worker for monitoring running goroutines
func (s *Agent) monitorWorker() {
	current := runtime.NumGoroutine()
	if current != s.goroutineCount {
		s.goroutineCount = current
		s.currentIteration = 0
		return
	}
	s.currentIteration++

	// cancel the monitoring goroutine if we discover
	// we've been stuck for some iterations.
	if s.currentIteration == defaultMonitorIteration {
		s.cancel()
		stackTraceFile := fmt.Sprintf("nuclei-stacktrace-%s.dump", xid.New().String())
		gologger.Error().Msgf("Detected hanging goroutine (count=%d/%d) = %s\n", current, s.goroutineCount, stackTraceFile)
		if err := ioutil.WriteFile(stackTraceFile, getStack(true), os.ModePerm); err != nil {
			gologger.Error().Msgf("Could not write stack trace for goroutines: %s\n", err)
		}
		os.Exit(1) // exit forcefully if we've been stuck
	}
}

// getStack returns full stack trace of the program
var getStack = func(all bool) []byte {
	for i := 1024 * 1024; ; i *= 2 {
		buf := make([]byte, i)
		if n := runtime.Stack(buf, all); n < i {
			return buf[:n-1]
		}
	}
}
