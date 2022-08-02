package protocolstate

import (
	"fmt"
	"net"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Dialer is a shared fastdialer instance for host DNS resolution
var Dialer *fastdialer.Dialer

// Init creates the Dialer instance based on user configuration
func Init(options *types.Options) error {
	if Dialer != nil {
		return nil
	}
	opts := fastdialer.DefaultOptions

	if options.Interface != "" {
		ief, err := net.InterfaceByName(options.Interface)
		if err != nil {
			return errors.Wrapf(err, "failed to get interface: `%s`", options.Interface)
		}
		addrs, err := ief.Addrs()
		if err != nil {
			return errors.Wrapf(err, "failed to get interface addresses for: `%s`", options.Interface)
		}
		var address net.IP
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					address = ipnet.IP
				}
			}
		}
		if address == nil {
			return fmt.Errorf("no suitable address found for interface: `%s`", options.Interface)
		}
		opts.Dialer = &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP: address,
			},
		}
	}

	if options.SystemResolvers {
		opts.EnableFallback = true
	}
	if options.ResolversFile != "" {
		opts.BaseResolvers = options.InternalResolversList
	}
	opts.WithDialerHistory = true
	opts.WithZTLS = options.ZTLS
	opts.SNIName = options.SNI
	dialer, err := fastdialer.NewDialer(opts)
	if err != nil {
		return errors.Wrap(err, "could not create dialer")
	}
	Dialer = dialer
	return nil
}

// Close closes the global shared fastdialer
func Close() {
	if Dialer != nil {
		Dialer.Close()
	}
}
