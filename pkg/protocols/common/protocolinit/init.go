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
	// unrelated unit tests that open relative paths. Production/CLI still apply
	// unless --no-sandbox / DisableSandbox is set. Sandbox package tests call
	// Apply directly.
	_ = sandbox.Apply(sandbox.Config{
		AllowedRoots: protocolstate.AllowedFileRoots(options),
		Disabled:     options.DisableSandbox || testing.Testing(),
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

func Close(executionId string) {
	protocolstate.Close(executionId)
}
