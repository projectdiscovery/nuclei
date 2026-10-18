package headless

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
)

const (
	headlessTimingTemplatesEnv = "NUCLEI_HEADLESS_TIMING_TEMPLATES"
	headlessTimingSampleRate   = 50
	headlessTimingSampleMin    = 30 * time.Second
	headlessTimingOutlierMin   = 5 * time.Minute
)

type headlessTimingTrace struct {
	templateID        string
	targetFingerprint string
	sampled           bool
	started           time.Time
	attempts          int
	errors            int
	rateWait          time.Duration
	contextCreate     time.Duration
	navigate          time.Duration
	waitLoad          time.Duration
	waitDialog        time.Duration
	otherActions      time.Duration
	runOther          time.Duration
	cleanup           time.Duration
}

func newHeadlessTimingTrace(templateID, target string) *headlessTimingTrace {
	selectedTemplates := os.Getenv(headlessTimingTemplatesEnv)
	if selectedTemplates == "" {
		return nil
	}
	selected := false
	for _, candidate := range strings.Split(selectedTemplates, ",") {
		if strings.TrimSpace(candidate) == templateID {
			selected = true
			break
		}
	}
	if !selected {
		return nil
	}

	fingerprint := sha256.Sum256([]byte(target))
	return &headlessTimingTrace{
		templateID:        templateID,
		targetFingerprint: fmt.Sprintf("%x", fingerprint[:8]),
		sampled:           binary.BigEndian.Uint64(fingerprint[:8])%headlessTimingSampleRate == 0,
		started:           time.Now(),
	}
}

func (t *headlessTimingTrace) recordRun(steps []*engine.Action, durations []time.Duration, elapsed time.Duration) {
	actions := time.Duration(0)
	if len(steps) != len(durations) {
		for _, duration := range durations {
			actions += duration
		}
		t.otherActions += actions
		if elapsed > actions {
			t.runOther += elapsed - actions
		}
		return
	}
	for index, duration := range durations {
		actions += duration
		if steps[index] == nil {
			t.otherActions += duration
			continue
		}
		switch steps[index].ActionType.ActionType {
		case engine.ActionNavigate:
			t.navigate += duration
		case engine.ActionWaitLoad:
			t.waitLoad += duration
		case engine.ActionWaitDialog:
			t.waitDialog += duration
		default:
			t.otherActions += duration
		}
	}
	if elapsed > actions {
		t.runOther += elapsed - actions
	}
}

func (t *headlessTimingTrace) child() *headlessTimingTrace {
	if t == nil {
		return nil
	}
	return &headlessTimingTrace{}
}

func (t *headlessTimingTrace) merge(other *headlessTimingTrace) {
	if t == nil || other == nil {
		return
	}
	t.attempts += other.attempts
	t.errors += other.errors
	t.rateWait += other.rateWait
	t.contextCreate += other.contextCreate
	t.navigate += other.navigate
	t.waitLoad += other.waitLoad
	t.waitDialog += other.waitDialog
	t.otherActions += other.otherActions
	t.runOther += other.runOther
	t.cleanup += other.cleanup
}

func (t *headlessTimingTrace) summary(elapsed time.Duration) (string, bool) {
	if elapsed < headlessTimingOutlierMin && (!t.sampled || elapsed < headlessTimingSampleMin) {
		return "", false
	}
	measured := t.rateWait + t.contextCreate + t.navigate + t.waitLoad + t.waitDialog + t.otherActions + t.runOther + t.cleanup
	unattributed := max(elapsed-measured, 0)
	return fmt.Sprintf(
		"slow headless timing template_id=%q target_fingerprint=%s attempts=%d errors=%d total_ms=%d rate_wait_ms=%d context_create_ms=%d navigate_ms=%d waitload_ms=%d waitdialog_ms=%d other_actions_ms=%d run_other_ms=%d cleanup_ms=%d unattributed_ms=%d",
		t.templateID, t.targetFingerprint, t.attempts, t.errors, elapsed.Milliseconds(), t.rateWait.Milliseconds(),
		t.contextCreate.Milliseconds(), t.navigate.Milliseconds(), t.waitLoad.Milliseconds(), t.waitDialog.Milliseconds(),
		t.otherActions.Milliseconds(), t.runOther.Milliseconds(), t.cleanup.Milliseconds(), unattributed.Milliseconds(),
	), true
}

func (t *headlessTimingTrace) emit() {
	if message, ok := t.summary(time.Since(t.started)); ok {
		gologger.Info().Msg(message)
	}
}
