package goexec

import "testing"

func TestMergeOptionsFromJavaScriptMap(t *testing.T) {
	opts := MergeOptions(DefaultExecutionOptions(), map[string]interface{}{
		"timeout":          float64(10),
		"output":           true,
		"output_method":    "SMB",
		"output_timeout":   float64(3),
		"no_delete_output": true,
		"directory":        `C:\Temp`,
		"endpoint":         "ncacn_np:[svcctl]",
		"epm_filter":       "ncacn_ip_tcp:",
		"no_sign":          true,
		"no_seal":          true,
		"max_output_size":  float64(42),
	})
	if opts.Timeout != 10 || !opts.Output || opts.OutputMethod != "smb" || opts.OutputTimeout != 3 {
		t.Fatalf("unexpected output options: %#v", opts)
	}
	if !opts.NoDeleteOutput || opts.Directory != `C:\Temp` || opts.Endpoint != "ncacn_np:[svcctl]" {
		t.Fatalf("unexpected execution options: %#v", opts)
	}
	if opts.EPMFilter != "ncacn_ip_tcp:" || !opts.NoSign || !opts.NoSeal || opts.MaxOutputSize != 42 {
		t.Fatalf("unexpected network options: %#v", opts)
	}
}

func TestMergeOptionsBooleanOverrides(t *testing.T) {
	base := DefaultExecutionOptions()
	base.Output = true
	base.NoSign = true
	base.NoSeal = true
	base.NoDeleteOutput = true
	base.EPM = true

	overridden := MergeOptions(base, map[string]interface{}{
		"output":           false,
		"no_sign":          false,
		"no_seal":          false,
		"no_delete_output": false,
		"epm":              false,
	})
	if overridden.Output || overridden.NoSign || overridden.NoSeal || overridden.NoDeleteOutput || overridden.EPM {
		t.Fatalf("explicit false should clear base booleans: %#v", overridden)
	}

	// absent keys must preserve the base values
	preserved := MergeOptions(base, map[string]interface{}{"timeout": float64(1)})
	if !preserved.Output || !preserved.NoSign || !preserved.NoSeal || !preserved.NoDeleteOutput || !preserved.EPM {
		t.Fatalf("absent keys should preserve base booleans: %#v", preserved)
	}
}

// TestMergeOptionsFromStructBooleans pins the (intentionally) one-way
// behavior of the struct-merge path: a `true` field in opts sets base to
// true, but a `false` field is treated as "unset" and leaves base alone.
// Callers that need to override a true→false must use the map path or
// mutate base directly.
func TestMergeOptionsFromStructBooleans(t *testing.T) {
	t.Run("true overrides false", func(t *testing.T) {
		base := DefaultExecutionOptions()
		merged := MergeOptions(base, ExecutionOptions{Output: true, NoSign: true, EPM: true})
		if !merged.Output || !merged.NoSign || !merged.EPM {
			t.Fatalf("struct true should set base bool: %#v", merged)
		}
	})

	t.Run("false leaves base true alone", func(t *testing.T) {
		base := DefaultExecutionOptions()
		base.Output = true
		base.NoSign = true
		base.EPM = true
		base.Timeout = 99

		merged := MergeOptions(base, ExecutionOptions{})
		if !merged.Output || !merged.NoSign || !merged.EPM {
			t.Fatalf("zero struct must not clear base booleans: %#v", merged)
		}
		if merged.Timeout != 99 {
			t.Fatalf("zero struct must not clear base Timeout: %d", merged.Timeout)
		}
	})

	t.Run("string and int overrides still apply", func(t *testing.T) {
		base := DefaultExecutionOptions()
		base.Output = true
		merged := MergeOptions(base, ExecutionOptions{Timeout: 5, Directory: `C:\Work`})
		if merged.Timeout != 5 || merged.Directory != `C:\Work` {
			t.Fatalf("struct non-bool overrides should apply: %#v", merged)
		}
		if !merged.Output {
			t.Fatalf("struct merge should leave unmentioned booleans alone: %#v", merged)
		}
	})
}
