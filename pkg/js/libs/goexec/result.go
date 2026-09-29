package goexec

// Result is returned by GoExec-backed Windows execution helper calls.
type Result struct {
	OK              bool          `json:"ok"`
	Module          string        `json:"module"`
	Method          string        `json:"method"`
	Target          string        `json:"target"`
	Stdout          string        `json:"stdout,omitempty"`
	Stderr          string        `json:"stderr,omitempty"`
	ExitCode        int           `json:"exit_code"`
	OutputCollected bool          `json:"output_collected"`
	OutputMethod    string        `json:"output_method,omitempty"`
	DurationMS      int64         `json:"duration_ms"`
	Error           string        `json:"error,omitempty"`
	Cleanup         CleanupResult `json:"cleanup"`
}

// CleanupResult reports helper-created artifact cleanup state.
type CleanupResult struct {
	Attempted bool     `json:"attempted"`
	Succeeded bool     `json:"succeeded"`
	Artifacts []string `json:"artifacts,omitempty"`
}

func newResult(req Request) *Result {
	return &Result{
		Module:   req.Module,
		Method:   req.Method,
		Target:   req.Target,
		ExitCode: -1,
		Cleanup: CleanupResult{
			Succeeded: true,
		},
	}
}

// Public returns a JavaScript-safe object with snake_case field names.
func (r *Result) Public() map[string]interface{} {
	if r == nil {
		return map[string]interface{}{}
	}
	cleanup := map[string]interface{}{
		"attempted": r.Cleanup.Attempted,
		"succeeded": r.Cleanup.Succeeded,
	}
	if len(r.Cleanup.Artifacts) > 0 {
		cleanup["artifacts"] = r.Cleanup.Artifacts
	}

	out := map[string]interface{}{
		"ok":               r.OK,
		"module":           r.Module,
		"method":           r.Method,
		"target":           r.Target,
		"stdout":           r.Stdout,
		"stderr":           r.Stderr,
		"exit_code":        r.ExitCode,
		"output_collected": r.OutputCollected,
		"duration_ms":      r.DurationMS,
		"cleanup":          cleanup,
	}
	if r.OutputMethod != "" {
		out["output_method"] = r.OutputMethod
	}
	if r.Error != "" {
		out["error"] = r.Error
	}
	return out
}

func truncateOutput(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	const suffix = "\n[truncated]"
	if max <= len(suffix) {
		return value[:max]
	}
	return value[:max-len(suffix)] + suffix
}
