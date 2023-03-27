package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/url"
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
	fileutil "github.com/projectdiscovery/utils/file"
)

// DoHealthCheck performs network and self-diagnostic checks
func DoHealthCheck(options *types.Options) string {
	internetTarget := "scanme.sh"
	dnsInternet := "1.1.1.1"
	ulimitmin := 1000 // Minimum free ulimit value
	var ipv4addresses string
	var ipv6addresses string

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

	// File permissions
	for _, filename := range []string{options.ConfigPath, config.GetIgnoreFilePath(), getTemplateCsf()} {
		fileTests["Read: "+filename] = checkFilePermissions(filename, "read")
		fileTests["Write: "+filename] = checkFilePermissions(filename, "write")
	}

	// Other Host information
	if runtime.GOOS != "windows" {
		// LINUX/UNIX Systems
		data["os"].(map[string]interface{})["ulimit"] = checkUlimit(data, ulimitmin)
	} else {
		// Windows Systems
	}

	//  DNS
	// - internetTarget
	// 	- host/nuclei DNS
	//  - internet DNS (fixed)
	// IP or name?
	if net.ParseIP(internetTarget) != nil {
		dnsTests["Public DNS ("+dnsInternet+") for "+internetTarget] = reverseLookup(internetTarget, dnsInternet)
		if iputil.IsIPv4(internetTarget) {
			ipv4addresses = internetTarget
		} else if iputil.IsIPv6(internetTarget) {
			ipv6addresses = internetTarget
		}

	} else {
		ipv4addresses, ipv6addresses = lookup(internetTarget, dnsInternet)

		if ipv4addresses != "" {
			dnsTests["Public IPv4 DNS ("+dnsInternet+") for "+internetTarget] = ipv4addresses
		} else {
			dnsTests["Public IPv4 DNS ("+dnsInternet+") for "+internetTarget] = "FAIL (No IPv4 address)"
		}
		if ipv6addresses != "" {
			dnsTests["Public IPv6 DNS ("+dnsInternet+") for "+internetTarget] = ipv6addresses
		} else {
			dnsTests["Public IPv6 DNS ("+dnsInternet+") for "+internetTarget] = "FAIL (No IPv6 address)"
		}
	}

	// Internet connectivity
	if ipv4addresses != "" {
		netTests["IPv4 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp4")
		netTests["IPv4 Traceroute ("+internetTarget+":80)"] = traceroute(ipv4addresses, "ipv4", options.HealthCheck)
	}
	if ipv6addresses != "" {
		netTests["IPv6 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp6")
		netTests["IPv6 Traceroute ("+internetTarget+":80)"] = traceroute(ipv6addresses, "ipv6", options.HealthCheck)
	}

	// send back formatted output
	return getOutput(data, options.HealthCheck)

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

// checkFilePermissions checks if a file is readable or writeable
func checkFilePermissions(filename string, test string) string {
	if test == "read" {
		ok, err := fileutil.IsReadable(filename)
		if err != nil {
			return fmt.Sprintf(" (%s)", err)
		} else if ok {
			return "Pass"
		} else {
			return "Fail"
		}

	} else if test == "write" {
		ok, err := fileutil.IsWriteable(filename)
		if err != nil {
			return fmt.Sprintf(" (%s)", err)
		} else if ok {
			return "Pass"
		} else {
			return "Fail"
		}
	}
	return "INVALID TEST"
}

// checkConnection checks if a connection can be made to a host
func checkConnection(host string, port int, protocol string) string {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.Dial(protocol, address)
	if err == nil && conn != nil {
		conn.Close()
	}
	if err != nil {
		return fmt.Sprintf("Fail (%s)", err)
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

// reverseLookup returns the reverse lookup of an IP address
func reverseLookup(ipAddr, dnsServer string) string {
	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, fmt.Sprintf("%s:53", dnsServer))
		},
	}

	names, _ := resolver.LookupAddr(context.Background(), ipAddr)
	if len(names) > 0 {
		return names[0]
	}
	return ""
}

// lookup returns the IP addresses for a name
func lookup(name, dnsServer string) (string, string) {
	var ipv4s []string
	var ipv6s []string

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, fmt.Sprintf("%s:53", dnsServer))
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
func traceroute(assetIPs, networkType, format string) string {
	if !iAmRoot() {
		return "Traceroute (" + networkType + ") to " + assetIPs + ": You must have root permissions to run traceroute"
	}

	maxHops := 20
	timeout := time.Second
	var results []string
	proto := "ip4:icmp"
	if networkType == "ipv6" {
		proto = "ip6:58"
	}

	// Use first resolved IP
	addresses := strings.Split(assetIPs, ", ")
	assetIP := addresses[0]
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
