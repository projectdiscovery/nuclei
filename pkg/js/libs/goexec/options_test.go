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
