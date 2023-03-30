package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// DoHealthCheck performs network and self-diagnostic checks
func DoHealthCheck(options *types.Options) string {
	const defaultTarget = "scanme.sh"
	const resolverPublic = "1.1.1.1"
	const ulimitmin = 1000 // Minimum free ulimit value
	internetTarget := defaultTarget
	var ipv4addresses string
	var ipv6addresses string

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
		},
		"program": map[string]interface{}{
			"version": config.Version,
		},
		"files":    map[string]interface{}{},
		"internet": map[string]interface{}{},
		"dns":      map[string]interface{}{},
		"net":      map[string]interface{}{},
	}
	fileTests := data["files"].(map[string]interface{})
	dnsTests := data["dns"].(map[string]interface{})
	netTests := data["net"].(map[string]interface{})

	// Begin tests

	// File permissions
	for _, filename := range []string{options.ConfigPath, config.GetIgnoreFilePath(), getTemplateCsf()} {
		fileTests["Read: "+filename] = checkFilePermissions(filename, "read")
		fileTests["Write: "+filename] = checkFilePermissions(filename, "write")
	}

	// Other Host information
	if runtime.GOOS != "windows" {
		// LINUX/UNIX Systems
		data["os"].(map[string]interface{})["ulimit"] = checkUlimit(data, ulimitmin)
	}

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
	netTests["IPv4 Ping ("+defaultTarget+")"] = ping(defaultTarget, "ipv4")

	// Network connectivity
	if ipv4addresses != "" {
		netTests["IPv4 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp4")
		netTests["IPv4 Traceroute ("+internetTarget+":80)"] = traceroute(ipv4addresses, "ipv4", options.HealthCheck)
		netTests["IPv4 Ping ("+internetTarget+")"] = ping(ipv4addresses, "ipv4")
	}
	if ipv6addresses != "" {
		netTests["IPv6 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp6")
		netTests["IPv6 Traceroute ("+internetTarget+":80)"] = traceroute(ipv6addresses, "ipv6", options.HealthCheck)
		netTests["IPv6 Ping ("+internetTarget+")"] = ping(ipv6addresses, "ipv6")

	}

	// send back formatted output
	return getOutput(data, options.HealthCheck)
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

// getTemplateCsf returns the path to the checksum file
func getTemplateCsf() string {
	cf, _ := config.ReadConfiguration()
	templatePath := ""
	if cf != nil {
		templatePath = cf.TemplatesDirectory
	}
	return filepath.Join(templatePath, "/", ".checksum")
}

// checkFilePermissions checks the permissions of a file
func checkFilePermissions(filename string, test string) string {
	// Determine permission to check based on test value
	var perm os.FileMode
	switch test {
	case "read":
		perm = 0400 // Read permission
	case "write":
		perm = 0200 // Write permission
	default:
		return fmt.Sprintf("Invalid test value: %s", test)
	}

	// Check if file exists
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Sprintf("File not found: %s", filename)
		} else {
			return err.Error()
		}
	}

	// Check file permission
	switch {
	case info.Mode().IsDir():
		return fmt.Sprintf("%s is a directory", filename)
	case info.Mode().Perm()&perm == perm:
		return "Pass"
	default:
		return "Fail"
	}
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
	return "Pass"
}

// getOutput returns the output in the specified format
func getOutput(data map[string]interface{}, format string) string {
	// Output format options - text (default), json, markdown
	if format == "json" {
		return mapToJson(data)
	} else if format == "md" {
		return mapToMarkdownTable(data, "Test", "Result")
	} else {
		return mapToTextTable(data, "Test", "Result")
	}
}

// checkUlimit checks the ulimit of the current user
func checkUlimit(data map[string]interface{}, difflimit int) string {
	var limit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	if (limit.Max - limit.Cur) <= uint64(difflimit) {
		return fmt.Sprintf("You may need to increase your file descriptor limit. %v/%v used", limit.Cur, limit.Max)
	} else {
		return "Pass"
	}
}

// mapToJson converts a map to a json string
func mapToJson(data map[string]interface{}) string {
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(json)
}

// mapToTextTable converts a map to a text table
func mapToTextTable(data map[string]interface{}, header1 string, header2 string) string {
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 0, 1, ' ', tabwriter.Debug|tabwriter.DiscardEmptyColumns)
	fmt.Fprintln(tw, header1+"\t"+header2)
	fmt.Fprintln(tw, "------\t------")

	for key, value := range data {
		fmt.Fprintln(tw, strings.ToUpper(key)+"\t")
		subMap, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		for subKey, subValue := range subMap {
			fmt.Fprintln(tw, subKey+"\t"+fmt.Sprintf("%v", subValue))
		}
	}
	tw.Flush()
	return b.String()
}

// mapToMarkdownTable converts a map to a markdown table
func mapToMarkdownTable(data map[string]interface{}, header1 string, header2 string) string {
	var output strings.Builder
	output.WriteString("| " + header1 + " | " + header2 + " | \n")
	output.WriteString("| --- | --- | \n")
	for key, value := range data {
		output.WriteString("| " + strings.ToUpper(key) + " | | \n")
		subMap, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		for subKey, subValue := range subMap {
			output.WriteString(("| " + subKey + "| " + fmt.Sprintf("%v", subValue) + " |\n"))
		}
	}
	return output.String()
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

// getFirstCsvEntry returns the first element of a comma separated string
func getFirstCsvEntry(values string) string {
	if values == "" {
		return ""
	}
	return strings.Split(values, ", ")[0]
}

// traceroute returns the traceroute of an IP address, both IPv6 and IPv4
// NOTE: Only works if we have root permission
func traceroute(assetIPs, networkType, format string) string {
	if !iAmRoot() {
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

	assetIP := getFirstCsvEntry(assetIPs)
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

	joinchar := " -> "
	if format == "json" {
		joinchar = "\n"
	}

	return strings.Join(results, joinchar)
}

// iAmRoot returns true if the current user is root
func iAmRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		panic(err)
	}
	return currentUser.Username == "root"
}

// ping returns the ping of an IP address, both IPv6 and IPv4
func ping(addresses, proto string) string {
	if !iAmRoot() {
		return "Ping: You must have root permissions to run this test"
	}
	assetIP := getFirstCsvEntry(addresses)

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
