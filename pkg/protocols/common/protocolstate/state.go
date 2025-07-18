package protocolstate

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"
	"golang.org/x/net/proxy"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/networkpolicy"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/expand"
	"github.com/projectdiscovery/retryablehttp-go"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var (
	dialers *mapsutil.SyncLockMap[string, *Dialers]
)

func init() {
	dialers = mapsutil.NewSyncLockMap[string, *Dialers]()
}

func GetDialers(ctx context.Context) *Dialers {
	executionContext := GetExecutionContext(ctx)
	dialers, ok := dialers.Get(executionContext.ExecutionID)
	if !ok {
		return nil
	}
	return dialers
}

func GetDialersWithId(id string) *Dialers {
	dialers, ok := dialers.Get(id)
	if !ok {
		return nil
	}
	return dialers
}

func ShouldInit(id string) bool {
	dialer, ok := dialers.Get(id)
	if !ok {
		return true
	}
	return dialer == nil
}

// Init creates the Dialers instance based on user configuration
func Init(options *types.Options) error {
	if GetDialersWithId(options.ExecutionId) != nil {
		return nil
	}

	return initDialers(options)
}

// initDialers is the internal implementation of Init
func initDialers(options *types.Options) error {
	opts := fastdialer.DefaultOptions
	opts.DialerTimeout = options.GetTimeouts().DialTimeout
	if options.DialerKeepAlive > 0 {
		opts.DialerKeepAlive = options.DialerKeepAlive
	}

	var expandedDenyList []string
	for _, excludeTarget := range options.ExcludeTargets {
		switch {
		case asn.IsASN(excludeTarget):
			expandedDenyList = append(expandedDenyList, expand.ASN(excludeTarget)...)
		default:
			expandedDenyList = append(expandedDenyList, excludeTarget)
		}
	}

	if options.RestrictLocalNetworkAccess {
		expandedDenyList = append(expandedDenyList, networkpolicy.DefaultIPv4DenylistRanges...)
		expandedDenyList = append(expandedDenyList, networkpolicy.DefaultIPv6DenylistRanges...)
	}
	npOptions := &networkpolicy.Options{
		DenyList: expandedDenyList,
	}
	opts.WithNetworkPolicyOptions = npOptions

	switch {
	case options.SourceIP != "" && options.Interface != "":
		isAssociated, err := isIpAssociatedWithInterface(options.SourceIP, options.Interface)
		if err != nil {
			return err
		}
		if isAssociated {
			opts.Dialer = &net.Dialer{
				LocalAddr: &net.TCPAddr{
					IP: net.ParseIP(options.SourceIP),
				},
			}
		} else {
			return fmt.Errorf("source ip (%s) is not associated with the interface (%s)", options.SourceIP, options.Interface)
		}
	case options.SourceIP != "":
		isAssociated, err := isIpAssociatedWithInterface(options.SourceIP, "any")
		if err != nil {
			return err
		}
		if isAssociated {
			opts.Dialer = &net.Dialer{
				LocalAddr: &net.TCPAddr{
					IP: net.ParseIP(options.SourceIP),
				},
			}
		} else {
			return fmt.Errorf("source ip (%s) is not associated with any network interface", options.SourceIP)
		}
	case options.Interface != "":
		ifadrr, err := interfaceAddress(options.Interface)
		if err != nil {
			return err
		}
		opts.Dialer = &net.Dialer{
			LocalAddr: &net.TCPAddr{
				IP: ifadrr,
			},
		}
	}
	if options.AliveSocksProxy != "" {
		proxyURL, err := url.Parse(options.AliveSocksProxy)
		if err != nil {
			return err
		}
		var forward *net.Dialer
		if opts.Dialer != nil {
			forward = opts.Dialer
		} else {
			forward = &net.Dialer{
				Timeout:   opts.DialerTimeout,
				KeepAlive: opts.DialerKeepAlive,
				DualStack: true,
			}
		}
		dialer, err := proxy.FromURL(proxyURL, forward)
		if err != nil {
			return err
		}
		opts.ProxyDialer = &dialer
	}

	if options.SystemResolvers {
		opts.ResolversFile = true
		opts.EnableFallback = true
	}
	if len(options.InternalResolversList) > 0 {
		opts.BaseResolvers = options.InternalResolversList
	}

	opts.Deny = append(opts.Deny, expandedDenyList...)

	opts.WithDialerHistory = true
	opts.SNIName = options.SNI
	// this instance is used in javascript protocol libraries and
	// dial history is required to get dialed ip of a host
	opts.WithDialerHistory = true

	// fastdialer now by default fallbacks to ztls when there are tls related errors
	dialer, err := fastdialer.NewDialer(opts)
	if err != nil {
		return errors.Wrap(err, "could not create dialer")
	}

	networkPolicy, _ := networkpolicy.New(*npOptions)

	dialersInstance := &Dialers{
		Fastdialer:             dialer,
		NetworkPolicy:          networkPolicy,
		HTTPClientPool:         mapsutil.NewSyncLockMap[string, *retryablehttp.Client](),
		LocalFileAccessAllowed: options.AllowLocalFileAccess,
	}

	_ = dialers.Set(options.ExecutionId, dialersInstance)

	// Set a custom dialer for the "nucleitcp" protocol.  This is just plain TCP, but it's registered
	// with a different name so that we do not clobber the "tcp" dialer in the event that nuclei is
	// being included as a package in another application.
	mysql.RegisterDialContext("nucleitcp", func(ctx context.Context, addr string) (net.Conn, error) {
		// Because we're not using the default TCP workflow, quietly add the default port
		// number if no port number was specified.
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr += ":3306"
		}

		executionId := ctx.Value("executionId").(string)
		dialer := GetDialersWithId(executionId)
		return dialer.Fastdialer.Dial(ctx, "tcp", addr)
	})

	StartActiveMemGuardian(context.Background())

	SetLfaAllowed(options)

	return nil
}

// isIpAssociatedWithInterface checks if the given IP is associated with the given interface.
func isIpAssociatedWithInterface(sourceIP, interfaceName string) (bool, error) {
	addrs, err := interfaceAddresses(interfaceName)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.String() == sourceIP {
				return true, nil
			}
		}
	}
	return false, nil
}

// interfaceAddress returns the first IPv4 address of the given interface.
func interfaceAddress(interfaceName string) (net.IP, error) {
	addrs, err := interfaceAddresses(interfaceName)
	if err != nil {
		return nil, err
	}
	var address net.IP
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				address = ipnet.IP
				break
			}
		}
	}
	if address == nil {
		return nil, fmt.Errorf("no suitable address found for interface: `%s`", interfaceName)
	}
	return address, nil
}

// interfaceAddresses returns all interface addresses.
func interfaceAddresses(interfaceName string) ([]net.Addr, error) {
	if interfaceName == "any" {
		return net.InterfaceAddrs()
	}
	ief, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get interface: `%s`", interfaceName)
	}
	addrs, err := ief.Addrs()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get interface addresses for: `%s`", interfaceName)
	}
	return addrs, nil
}

// Close closes the global shared fastdialer
func Close(executionId string) {
	dialersInstance, ok := dialers.Get(executionId)
	if !ok {
		return
	}

	if dialersInstance != nil {
		dialersInstance.Fastdialer.Close()
	}

	dialers.Delete(executionId)

	if dialers.IsEmpty() {
		StopActiveMemGuardian()
	}
}
