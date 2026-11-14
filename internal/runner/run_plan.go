package runner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// planFollowInterval is how often a running plan picks up entries appended to
// it and ids appended to its cancel log.
var planFollowInterval = time.Second

// planRun limits a scan to the entries of a plan file and appends the id of
// each finished entry to the plan's done log, so running the plan again skips
// them. Ids are derived from what an entry runs, not from its position, so the
// log still applies after the plan is written again for changed targets or
// templates.
//
// While it runs, entries appended to the plan and ids appended to its cancel
// log apply to the pairs the scan has not reached yet, so an agent can steer
// the scan through files alone; the done log is its progress.
type planRun struct {
	mu      sync.Mutex
	entries map[uint64]plannedEntry
	// done holds finished origin groups by the id of their first entry; an
	// entry outside a group is its own group
	done map[uint64]struct{}
	// cancelled holds ids from the cancel log; the id of a group's first entry
	// cancels the group
	cancelled map[uint64]struct{}
	plan      tailedFile
	cancel    tailedFile
	log       *os.File
	logErr    error
	// resumed counts the entries finished before this run
	resumed int
	stop    func()
}

type plannedEntry struct {
	group uint64
	seen  bool
}

func planDoneLog(planFile string) string {
	return planFile + ".done"
}

func planCancelLog(planFile string) string {
	return planFile + ".cancel"
}

func openPlanRun(planFile string) (*planRun, error) {
	run := &planRun{
		entries:   make(map[uint64]plannedEntry),
		done:      make(map[uint64]struct{}),
		cancelled: make(map[uint64]struct{}),
		plan:      tailedFile{path: planFile},
		cancel:    tailedFile{path: planCancelLog(planFile)},
	}
	var lineErr error
	firstErr := func(err error) {
		if lineErr == nil {
			lineErr = err
		}
	}
	if err := run.plan.read(true, run.addEntry, firstErr); err != nil {
		return nil, err
	}
	if lineErr != nil {
		return nil, lineErr
	}
	if err := run.cancel.read(false, run.addCancel, nil); err != nil {
		return nil, err
	}
	if err := run.readDoneLog(planDoneLog(planFile)); err != nil {
		return nil, err
	}
	log, err := os.OpenFile(planDoneLog(planFile), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	// an interrupted write leaves a partial line, which the next id must not
	// extend
	if info, err := log.Stat(); err == nil && info.Size() > 0 {
		last := make([]byte, 1)
		if _, err := log.ReadAt(last, info.Size()-1); err == nil && last[0] != '\n' {
			_, _ = log.WriteString("\n")
		}
	}
	run.log = log
	return run, nil
}

// tailedFile reads the lines appended to a file since the last read.
type tailedFile struct {
	path   string
	offset int64
	number int
}

// read passes each complete new line to fn and its error to onErr. A line
// still being written is left for the next read, unless final is set.
func (tail *tailedFile) read(final bool, fn func([]byte) error, onErr func(error)) error {
	file, err := os.Open(tail.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Seek(tail.offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(file)
	for {
		line, readErr := reader.ReadBytes('\n')
		if readErr == io.EOF && !final {
			return nil
		}
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		if len(line) == 0 {
			return nil
		}
		tail.offset += int64(len(line))
		tail.number++
		if line = bytes.TrimSpace(line); len(line) > 0 {
			if err := fn(line); err != nil && onErr != nil {
				onErr(fmt.Errorf("%s:%d: %w", tail.path, tail.number, err))
			}
		}
		if readErr == io.EOF {
			return nil
		}
	}
}

func (run *planRun) addEntry(line []byte) error {
	var entry struct {
		ID            string `json:"id"`
		AlternativeTo string `json:"alternative-to"`
	}
	if err := json.Unmarshal(line, &entry); err != nil {
		return err
	}
	// the summary line has no id
	if entry.ID == "" {
		return nil
	}
	id, ok := parsePlanID(entry.ID)
	if !ok {
		return fmt.Errorf("invalid id %q", entry.ID)
	}
	group := id
	if entry.AlternativeTo != "" {
		if group, ok = parsePlanID(entry.AlternativeTo); !ok {
			return fmt.Errorf("invalid alternative-to %q", entry.AlternativeTo)
		}
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	if _, planned := run.entries[id]; !planned {
		run.entries[id] = plannedEntry{group: group}
	}
	return nil
}

func (run *planRun) addCancel(line []byte) error {
	id, ok := parsePlanID(string(line))
	if !ok {
		return fmt.Errorf("invalid id %q", line)
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	run.cancelled[id] = struct{}{}
	return nil
}

// follow picks up the plan's new entries and cancelled ids until the run is
// closed.
func (run *planRun) follow(interval time.Duration, onErr func(error)) {
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				run.poll(onErr)
			}
		}
	}()
	run.stop = func() {
		close(stop)
		<-stopped
	}
}

func (run *planRun) poll(onErr func(error)) {
	if err := run.plan.read(false, run.addEntry, onErr); err != nil {
		onErr(err)
	}
	if err := run.cancel.read(false, run.addCancel, onErr); err != nil {
		onErr(err)
	}
}

func (run *planRun) readDoneLog(path string) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// a partial line from an interrupted write does not parse and is
		// run again
		id, ok := parsePlanID(scanner.Text())
		if !ok {
			continue
		}
		if entry, planned := run.entries[id]; planned {
			run.done[entry.group] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for _, entry := range run.entries {
		if _, done := run.done[entry.group]; done {
			run.resumed++
		}
	}
	return nil
}

// parsePlanID keeps ids as integers, which a plan of millions of entries
// holds in a fraction of the memory of strings.
func parsePlanID(id string) (uint64, bool) {
	if len(id) != 16 {
		return 0, false
	}
	value, err := strconv.ParseUint(id, 16, 64)
	return value, err == nil
}

func (run *planRun) Skip(id string) bool {
	key, ok := parsePlanID(id)
	if !ok {
		return true
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	entry, planned := run.entries[key]
	if !planned {
		return true
	}
	if !entry.seen {
		entry.seen = true
		run.entries[key] = entry
	}
	if run.isCancelled(key, entry) {
		return true
	}
	_, done := run.done[entry.group]
	return done
}

func (run *planRun) isCancelled(id uint64, entry plannedEntry) bool {
	_, cancelled := run.cancelled[id]
	_, groupCancelled := run.cancelled[entry.group]
	return cancelled || groupCancelled
}

func (run *planRun) Finished(id string) {
	key, ok := parsePlanID(id)
	if !ok {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	entry, planned := run.entries[key]
	if !planned {
		return
	}
	run.done[entry.group] = struct{}{}
	// written straight to the file: ctrl+c exits without running defers
	if _, err := run.log.WriteString(id + "\n"); err != nil && run.logErr == nil {
		run.logErr = err
	}
}

// unreached counts unfinished entries the scan did not get to: those of a
// host it found unresponsive, those appended after the scan passed their
// pair, and those it does not have because it runs with other templates,
// targets or options than the plan. Cancelled entries are not counted.
func (run *planRun) unreached() int {
	run.mu.Lock()
	defer run.mu.Unlock()
	count := 0
	for id, entry := range run.entries {
		if _, done := run.done[entry.group]; !done && !entry.seen && !run.isCancelled(id, entry) {
			count++
		}
	}
	return count
}

func (run *planRun) close() error {
	if run.stop != nil {
		run.stop()
	}
	if err := run.log.Close(); err != nil && run.logErr == nil {
		run.logErr = err
	}
	return run.logErr
}

// finishPlanRun closes the done log and reports the entries left to run.
func (r *Runner) finishPlanRun(run *planRun) {
	if err := run.close(); err != nil {
		r.Logger.Error().Msgf("Could not write %s: %s", planDoneLog(r.options.RunPlanFile), err)
	}
	if unreached := run.unreached(); unreached > 0 {
		r.Logger.Info().Msgf("%d plan entries did not run; running the plan again retries them. Entries run only when the scan has the templates, targets and options the plan was written with", unreached)
	}
}
