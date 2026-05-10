package goexec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResultPublicUsesSnakeCaseFields(t *testing.T) {
	result := &Result{
		OK:              true,
		Module:          "wmi",
		Method:          "command",
		Target:          "host",
		Stdout:          "ok",
		ExitCode:        0,
		OutputCollected: true,
		OutputMethod:    "smb",
		DurationMS:      12,
		Cleanup:         CleanupResult{Attempted: true, Succeeded: true, Artifacts: []string{`C:\Windows\Temp\x`}},
	}
	data, err := json.Marshal(result.Public())
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, field := range []string{"output_collected", "output_method", "duration_ms", "exit_code"} {
		if !strings.Contains(got, field) {
			t.Fatalf("expected field %q in %s", field, got)
		}
	}
}

func TestTruncateOutput(t *testing.T) {
	got := truncateOutput("abcdefghijklmnopqrstuvwxyz", 15)
	if !strings.Contains(got, "[truncated]") || len(got) > 15 {
		t.Fatalf("unexpected truncated output %q", got)
	}
}
