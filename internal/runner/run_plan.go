package runner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// planRun limits a scan to the entries of a plan file and appends the id of
// each finished entry to the plan's done log, so running the plan again skips
// them. Ids are derived from what an entry runs, not from its position, so the
// log still applies after the plan is written again for changed targets or
// templates.
type planRun struct {
	mu      sync.Mutex
	entries map[uint64]plannedEntry
	// done holds finished origin groups by the id of their first entry; an
	// entry outside a group is its own group
	done   map[uint64]struct{}
	log    *os.File
	logErr error
	// resumed counts the entries finished before this run
	resumed int
}

type plannedEntry struct {
	group uint64
	seen  bool
}

func planDoneLog(planFile string) string {
	return planFile + ".done"
}

func openPlanRun(planFile string) (*planRun, error) {
	run := &planRun{entries: make(map[uint64]plannedEntry), done: make(map[uint64]struct{})}
	if err := run.readPlan(planFile); err != nil {
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

func (run *planRun) readPlan(planFile string) error {
	file, err := os.Open(planFile)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	reader := bufio.NewReader(file)
	for number := 1; ; number++ {
		line, readErr := reader.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var entry struct {
				ID            string `json:"id"`
				AlternativeTo string `json:"alternative-to"`
			}
			if err := json.Unmarshal(line, &entry); err != nil {
				return fmt.Errorf("%s:%d: %w", planFile, number, err)
			}
			// the summary line has no id
			if entry.ID != "" {
				id, ok := parsePlanID(entry.ID)
				if !ok {
					return fmt.Errorf("%s:%d: invalid id %q", planFile, number, entry.ID)
				}
				group := id
				if entry.AlternativeTo != "" {
					if group, ok = parsePlanID(entry.AlternativeTo); !ok {
						return fmt.Errorf("%s:%d: invalid alternative-to %q", planFile, number, entry.AlternativeTo)
					}
				}
				run.entries[id] = plannedEntry{group: group}
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
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
	_, done := run.done[entry.group]
	return done
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
// host it found unresponsive, and those it does not have because it runs
// with other templates, targets or options than the plan.
func (run *planRun) unreached() int {
	run.mu.Lock()
	defer run.mu.Unlock()
	count := 0
	for _, entry := range run.entries {
		if _, done := run.done[entry.group]; !done && !entry.seen {
			count++
		}
	}
	return count
}

func (run *planRun) close() error {
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
