package protocolinit

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/signerpool"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Init initializes the client pools for the protocols
func Init(options *types.Options) error {
	if err := protocolstate.Init(options); err != nil {
		return err
	}
	if err := httpclientpool.Init(options); err != nil {
		return err
	}
	if err := signerpool.Init(options); err != nil {
		return err
	}
	if err := compiler.Init(options); err != nil {
		return err
	}
	return nil
}

func Close() {
	protocolstate.Close()
}
