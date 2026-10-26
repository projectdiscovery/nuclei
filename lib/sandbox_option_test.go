package nuclei

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestProcessSandboxIsOptInForSDK(t *testing.T) {
	e := &NucleiEngine{opts: types.DefaultOptions()}
	if protocolinit.ProcessSandboxEnabled(e.opts) {
		t.Fatal("SDK default options enable the process-wide sandbox")
	}

	if err := EnableProcessSandbox()(e); err != nil {
		t.Fatalf("EnableProcessSandbox: %v", err)
	}
	if !protocolinit.ProcessSandboxEnabled(e.opts) {
		t.Fatal("EnableProcessSandbox did not enable the process-wide sandbox")
	}

	e.opts.DisableSandbox = true
	if protocolinit.ProcessSandboxEnabled(e.opts) {
		t.Fatal("DisableSandbox did not override EnableProcessSandbox")
	}
}
