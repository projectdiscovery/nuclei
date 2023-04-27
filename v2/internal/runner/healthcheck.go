package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"

	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/projectdiscovery/fdmax"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	file "github.com/projectdiscovery/utils/file"
	permission "github.com/projectdiscovery/utils/permission"
)

// DoHealthCheck performs network and self-diagnostic checks
// If a target is specified via -u, it will perform additional checks
func DoHealthCheck(options *types.Options) string {
	const defaultTarget = "scanme.sh"
	const resolverPublic = "1.1.1.1"
	const ulimitmin = 1000 // Minimum free ulimit value
	internetTarget := defaultTarget
	var ipv4addresses string
	var ipv6addresses string
	adminPriv := permission.IsRoot

	var resolvers []string
	if options.ResolversFile != "" {
		resolvers = options.InternalResolversList
	} else {
		resolvers = []string{resolverPublic}
	}

	if len(options.Targets) > 0 {
		if iputil.IsIPv6(options.Targets[0]) {
			internetTarget = options.Targets[0]
		} else {
			parsedURL, err := url.Parse(options.Targets[0])
			if err == nil {
				internetTarget = parsedURL.Host
			}
			if internetTarget == "" {
				internetTarget = options.Targets[0]
			}
		}
	}

	// Data structures
	data := map[string]interface{}{
		"os": map[string]interface{}{
			"name":      runtime.GOOS,
			"arch":      runtime.GOARCH,
			"goVersion": runtime.Version(),
			"compiler":  runtime.Compiler,
			"admin":     adminPriv,
		},
		"program": map[string]interface{}{
			"version": config.Version,
		},
		"files": map[string]interface{}{},
		// "internet": map[string]interface{}{},
		"dns":   map[string]interface{}{},
		"net":   map[string]interface{}{},
		"asset": map[string]interface{}{},
	}
	assetInfo := data["asset"].(map[string]interface{})
	fileTests := data["files"].(map[string]interface{})
	dnsTests := data["dns"].(map[string]interface{})
	netTests := data["net"].(map[string]interface{})
	assetInfo["target"] = internetTarget

	// Begin tests

	// File permissions
	for _, filename := range []string{config.DefaultConfig.GetFlagsConfigFilePath(), config.DefaultConfig.GetIgnoreFilePath(), config.DefaultConfig.GetChecksumFilePath()} {
		if ok, _ := file.IsReadable(filename); ok {
			fileTests["Read: "+filename] = "Pass"
		} else {
			fileTests["Read: "+filename] = "Fail"
		}
		if ok, _ := file.IsWriteable(filename); ok {
			fileTests["Write: "+filename] = "Pass"
		} else {
			fileTests["Write: "+filename] = "Fail"
		}
	}

	// Other Host information
	data["os"].(map[string]interface{})["ulimit"] = checkUlimit(data, ulimitmin)

	// Test each DNS resolver set in config and the default resolver
	resolvers = addIfNotExists(resolvers, resolverPublic)
	for _, resolverCfg := range resolvers {
		for _, host := range []string{internetTarget, defaultTarget} {
			ipv4addresses, ipv6addresses = getAddresses(host, resolverCfg)

			if ipv4addresses != "" {
				dnsTests["Public IPv4 DNS ("+resolverCfg+") for "+host] = ipv4addresses
			} else {
				dnsTests["Public IPv4 DNS ("+resolverCfg+") for "+host] = "FAIL (No IPv4 address)"
			}

			if ipv6addresses != "" {
				dnsTests["Public IPv6 DNS ("+resolverCfg+") for "+host] = ipv6addresses
			} else {
				dnsTests["Public IPv6 DNS ("+resolverCfg+") for "+host] = "FAIL (No IPv6 address)"
			}
		}
	}
	// Rather than the last resolver in the list, use the first one for final answer
	ipv4addresses, ipv6addresses = getAddresses(internetTarget, resolvers[0])

	// Default target internet tests
	netTests["IPv4 Ping ("+defaultTarget+")"] = ping(defaultTarget, "ipv4", adminPriv)

	// Network connectivity
	if ipv4addresses != "" {
		netTests["IPv4 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp4")
		netTests["IPv4 Traceroute ("+internetTarget+":80)"] = traceroute(ipv4addresses, "ipv4", adminPriv)
		netTests["IPv4 Ping ("+internetTarget+")"] = ping(ipv4addresses, "ipv4", adminPriv)
	}
	if ipv6addresses != "" {
		netTests["IPv6 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp6")
		netTests["IPv6 Traceroute ("+internetTarget+":80)"] = traceroute(ipv6addresses, "ipv6", adminPriv)
		netTests["IPv6 Ping ("+internetTarget+")"] = ping(ipv6addresses, "ipv6", adminPriv)

	}

	// send back formatted output
	return mapToJson(data)
}

// addIfNotExists adds an element to a slice if it doesn't already exist
func addIfNotExists(slice []string, element string) []string {
	for _, e := range slice {
		if e == element {
			// Element already exists in slice, return original slice
			return slice
		}
	}
	// Element doesn't exist in slice, append to slice and return
	return append(slice, element)
}

// getAddresses returns the IPv4 and IPv6 addresses for a host
func getAddresses(target, dnsServer string) (string, string) {
	var ipv4addresses string
	var ipv6addresses string
	if net.ParseIP(target) != nil {
		if iputil.IsIPv4(target) {
			ipv4addresses = target
		} else if iputil.IsIPv6(target) {
			ipv6addresses = target
		}
	} else {
		ipv4addresses, ipv6addresses = lookup(target, dnsServer)
	}
	return ipv4addresses, ipv6addresses
}

// checkConnection checks if a connection can be made to a host
func checkConnection(host string, port int, protocol string) string {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.Dial(protocol, address)
	if err != nil {
		return fmt.Sprintf("Fail (%s)", err)
	}

	if conn != nil {
		conn.Close()
	}
	return "Success"
}

// mapToJson converts a map to a json string
func mapToJson(data map[string]interface{}) string {
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(json)
}

// lookup returns the IP addresses for a name
func lookup(name, dnsServer string) (string, string) {
	var ipv4s []string
	var ipv6s []string

	// resolvers from config can be in the form of ip:port
	// if not, add port 53
	if !strings.Contains(dnsServer, ":") {
		dnsServer = dnsServer + ":53"
	}

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, dnsServer)
		},
	}

	ips, err := resolver.LookupIPAddr(context.Background(), name)
	if err != nil {
		return "", ""
	}

	for _, ip := range ips {
		if ip.IP.To4() != nil {
			ipv4s = append(ipv4s, ip.IP.String())
		} else if ip.IP.To16() != nil {
			ipv6s = append(ipv6s, ip.IP.String())
		}
	}

	return strings.Join(ipv4s, ", "), strings.Join(ipv6s, ", ")
}

// traceroute returns the traceroute of an IP address, both IPv6 and IPv4
// NOTE: Only works if we have root permission
// TODO: Add support for Windows
func traceroute(assetIPs string, networkType string, adminPriv bool) string {
	if !adminPriv {
		return "Traceroute: You must have root permissions to run this test"
	}

	maxHops := 15
	timeout := time.Second
	var prevHopIP net.IP
	var results []string
	proto := "ip4:icmp"
	if networkType == "ipv6" {
		proto = "ip6:58"
	}

	assetIP := strings.Split(assetIPs, ", ")[0]
	ipaddr, _ := net.ResolveIPAddr("ip", assetIP)

	listener, err := icmp.ListenPacket(proto, "::")
	if err != nil {
		return "Traceroute (" + networkType + ") to " + assetIP + ":" + err.Error()
	}
	defer listener.Close()

	for i := 1; i <= maxHops; i++ {
		if networkType == "ipv4" {
			listener.IPv4PacketConn().SetTTL(i)
		} else {
			listener.IPv6PacketConn().SetHopLimit(i)
		}

		var message icmp.Message
		if networkType == "ipv4" {
			message = icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   rand.Intn(0xffff + 1),
					Seq:  1,
					Data: []byte(""),
				},
			}
		} else {
			message = icmp.Message{
				Type: ipv6.ICMPTypeEchoRequest,
				Code: 0,
				Body: &icmp.Echo{
					ID:   rand.Intn(0xffff + 1),
					Seq:  1,
					Data: []byte(""),
				},
			}
		}

		b, err := message.Marshal(nil)
		if err != nil {
			return "Traceroute (" + networkType + ") to " + assetIP + ":" + err.Error()
		}
		_, err = listener.WriteTo(b, ipaddr)
		if err != nil {
			return "Traceroute (" + networkType + ") to " + assetIP + ":" + err.Error()
		}

		reply := make([]byte, 1500)
		err = listener.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return "Traceroute (" + networkType + ") to " + assetIP + ":" + err.Error()
		}

		n, peer, err := listener.ReadFrom(reply)
		if err != nil {
			results = append(results, fmt.Sprintf("%d. *", i))
			continue
		}

		if prevHopIP != nil && prevHopIP.Equal(peer.(*net.IPAddr).IP) {
			break
		}
		prevHopIP = peer.(*net.IPAddr).IP

		var rm *icmp.Message
		if networkType == "ipv4" {
			rm, err = icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
		} else {
			rm, err = icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), reply[:n])
		}
		if err != nil {
			return "Traceroute (" + networkType + ") to " + assetIP + ":" + err.Error()
		}

		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded, ipv6.ICMPTypeTimeExceeded:
			results = append(results, fmt.Sprintf("%d. %s", i, peer))
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			results = append(results, fmt.Sprintf("%d. %s", i, peer))
		default:
			msg := fmt.Sprintf("Traceroute rec'd unexpected ICMP message: %+v", rm)
			results = append(results, msg)
		}
	}

	return strings.Join(results, "\n")
}

// ping performs a ping of an IP address, both IPv6 and IPv4 as requested
func ping(addresses, proto string, adminPriv bool) string {
	if !adminPriv {
		return "Ping: You must have root permissions to run this test"
	}
	assetIP := strings.Split(addresses, ", ")[0]

	var err error
	var conn net.PacketConn
	var ipAddr *net.IPAddr
	if proto == "ipv6" {
		conn, err = net.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return "Ping to " + assetIP + ": " + err.Error()
		}
		ipAddr, err = net.ResolveIPAddr("ip6", assetIP)
		if err != nil {
			return "Ping to " + assetIP + ": " + err.Error()
		}
	} else if proto == "ipv4" {
		conn, err = net.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return "Ping to " + assetIP + ": " + err.Error()
		}
		ipAddr, err = net.ResolveIPAddr("ip4", assetIP)
		if err != nil {
			return "Ping to " + assetIP + ": " + err.Error()
		}
	}
	defer conn.Close()

	// Build ICMP message
	echo := icmp.Echo{
		ID:   os.Getpid() & 0xffff,
		Seq:  1,
		Data: []byte(""),
	}
	var msg icmp.Message
	if proto == "ipv6" {

		msg = icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &echo,
		}
	} else if proto == "ipv4" {
		msg = icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &echo,
		}
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return "Ping to " + assetIP + ": " + err.Error()
	}

	start := time.Now()
	_, err = conn.WriteTo(msgBytes, ipAddr)
	if err != nil {
		return "Ping to " + assetIP + ": " + err.Error()
	}

	reply := make([]byte, 56)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _, err = conn.ReadFrom(reply)
	if err != nil {
		return "Ping to " + assetIP + ": " + err.Error()
	}
	duration := time.Since(start)
	return fmt.Sprintf("Ping to %s: %s", assetIP, duration.String())
}

// checkUlimit checks the ulimit of the current user
func checkUlimit(data map[string]interface{}, difflimit int) string {
	limit, err := fdmax.Get()
	if err != nil {
		return "Fail: " + err.Error()
	}
	if (limit.Max - limit.Current) <= uint64(difflimit) {
		return fmt.Sprintf("You may need to increase your file descriptor limit. %v/%v used", limit.Current, limit.Max)
	}
	return "Pass"
}
