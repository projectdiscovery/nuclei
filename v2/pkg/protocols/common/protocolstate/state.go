package protocolstate

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

var Dialer *fastdialer.Dialer

func Init(options *types.Options) error {
	opts := fastdialer.DefaultOptions
	if options.SystemResolvers {
		opts.EnableFallback = true
	}
	if options.ResolversFile != "" {
		opts.BaseResolvers = options.InternalResolversList
	}
	dialer, err := fastdialer.NewDialer(opts)
	if err != nil {
		errors.Wrap(err, "could not create dialer")
	}
	Dialer = dialer
	return nil
}

func Close() {
	if Dialer != nil {
		Dialer.Close()
	}
}
