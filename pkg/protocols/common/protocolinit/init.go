package protocolinit

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/sandbox"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns/dnsclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/signerpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network/networkclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/whois/rdapclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	_ "github.com/projectdiscovery/utils/global"
)

// Init initializes the client pools for the protocols
func Init(options *types.Options) error {
	if err := protocolstate.Init(options); err != nil {
		return err
	}
	// Landlock is process-wide and irreversible. Under `go test` package CWDs
	// and fixture trees are not in AllowedFileRoots, so applying it would break
	// unrelated unit tests that open relative paths. Sandbox package tests call
	// Apply directly.
	_ = sandbox.Apply(sandbox.Config{
		AllowedRoots:   protocolstate.SandboxFileRoots(options),
		OwnedRoots:     protocolstate.SandboxOwnedFileRoots(options),
		Disabled:       !ProcessSandboxEnabled(options) || testing.Testing(),
		IncludeRuntime: true,
	})
	if err := dnsclientpool.Init(options); err != nil {
		return err
	}
	if err := signerpool.Init(options); err != nil {
		return err
	}
	if err := networkclientpool.Init(options); err != nil {
		return err
	}
	if err := rdapclientpool.Init(options); err != nil {
		return err
	}
	if err := compiler.Init(options); err != nil {
		return err
	}
	return nil
}

// ProcessSandboxEnabled reports whether Init applies the process-wide OS
// filesystem sandbox. It is opt-in through EnableProcessSandbox, which the
// nuclei CLI sets and SDK callers must request explicitly, because the sandbox
// confines the whole host process and cannot be undone. -no-sandbox
// (DisableSandbox) always turns it off.
func ProcessSandboxEnabled(options *types.Options) bool {
	return options != nil && options.EnableProcessSandbox && !options.DisableSandbox
}

func Close(executionId string) {
	protocolstate.Close(executionId)
}
