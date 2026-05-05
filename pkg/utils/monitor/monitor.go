// Package monitor implements a goroutine based monitoring for
// detecting stuck scanner processes and dumping stack and other
// relevant information for investigation.
package monitor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/gostackparse"
	"github.com/projectdiscovery/gologger"
	permissionutil "github.com/projectdiscovery/utils/permission"
	unitutils "github.com/projectdiscovery/utils/unit"
	"github.com/rs/xid"
)

// Agent is an agent for monitoring hanging programs
type Agent struct {
	lastStack []string
	callbacks []Callback

	goroutineCount   int
	currentIteration int // number of times we've checked hang

	lock sync.Mutex
}

const defaultMonitorIteration = 6

// NewStackMonitor returns a new stack monitor instance
func NewStackMonitor() *Agent {
	return &Agent{}
}

// Callback when crash is detected and stack trace is saved to disk
type Callback func(dumpID string) error

// RegisterCallback adds a callback to perform additional operations before bailing out.
func (s *Agent) RegisterCallback(callback Callback) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.callbacks = append(s.callbacks, callback)
}

func (s *Agent) Start(interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(interval)

	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
			case <-ticker.C:
				s.monitorWorker(cancel)
			default:
				continue
			}
		}
	}()
	return cancel
}

// monitorWorker is a worker for monitoring running goroutines
func (s *Agent) monitorWorker(cancel context.CancelFunc) {
	current := runtime.NumGoroutine()
	if current != s.goroutineCount {
		s.goroutineCount = current
		s.currentIteration = 0
		return
	}
	s.currentIteration++

	if s.currentIteration == defaultMonitorIteration-1 {
		lastStackTrace := generateStackTraceSlice(getStack(true))
		s.lastStack = lastStackTrace
		return
	}

	// cancel the monitoring goroutine if we discover
	// we've been stuck for some iterations.
	if s.currentIteration == defaultMonitorIteration {
		currentStack := getStack(true)

		// Bail out if the stacks don't match from previous iteration
		newStack := generateStackTraceSlice(currentStack)
		if !compareStringSliceEqual(s.lastStack, newStack) {
			s.currentIteration = 0
			return
		}

		cancel()
		dumpID := xid.New().String()
		stackTraceFile := fmt.Sprintf("nuclei-stacktrace-%s.dump", dumpID)
		gologger.Error().Msgf("Detected hanging goroutine (count=%d/%d) = %s\n", current, s.goroutineCount, stackTraceFile)
		if err := os.WriteFile(stackTraceFile, currentStack, permissionutil.ConfigFilePermission); err != nil {
			gologger.Error().Msgf("Could not write stack trace for goroutines: %s\n", err)
		}

		s.lock.Lock()
		callbacks := s.callbacks
		s.lock.Unlock()
		for _, callback := range callbacks {
			if err := callback(dumpID); err != nil {
				gologger.Error().Msgf("Stack monitor callback error: %s\n", err)
			}
		}

		os.Exit(1) // exit forcefully if we've been stuck
	}
}

// getStack returns full stack trace of the program
var getStack = func(all bool) []byte {
	for i := unitutils.Mega; ; i *= 2 {
		buf := make([]byte, i)
		if n := runtime.Stack(buf, all); n < i {
			return buf[:n-1]
		}
	}
}

// generateStackTraceSlice returns a list of current stack in string slice format
func generateStackTraceSlice(stack []byte) []string {
	goroutines, _ := gostackparse.Parse(bytes.NewReader(stack))

	var builder strings.Builder
	var stackList []string
	for _, goroutine := range goroutines {
		builder.WriteString(goroutine.State)
		builder.WriteString("|")

		for _, frame := range goroutine.Stack {
			builder.WriteString(frame.Func)
			builder.WriteString(";")
		}
		stackList = append(stackList, builder.String())
		builder.Reset()
	}
	return stackList
}

// compareStringSliceEqual compares two string slices for equality without order
func compareStringSliceEqual(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	diff := make(map[string]int, len(first))
	for _, x := range first {
		diff[x]++
	}
	for _, y := range second {
		if _, ok := diff[y]; !ok {
			return false
		}
		diff[y] -= 1
		if diff[y] == 0 {
			delete(diff, y)
		}
	}
	return len(diff) == 0
}
