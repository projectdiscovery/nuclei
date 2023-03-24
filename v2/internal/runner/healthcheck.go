package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

// DoHealthCheck performs network and self-diagnostic checks
func DoHealthCheck(options *types.Options) string {
	internetTarget := "scanme.sh:80"
	dnsInternet := "8.8.8.8"
	ulimitmin := 1000 // Minimum free ulimit value

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
	fmt.Printf("Using networking target: " + internetTarget + "\n\n")
	// if internetTarget == "" {
	// 	internetTarget = "scanme.sh:80"
	// }

	fmt.Print("Using networking target: " + internetTarget + "\n\n")

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
	}
	fileTests := data["files"].(map[string]interface{})
	internetTests := data["internet"].(map[string]interface{})
	dnsTests := data["dns"].(map[string]interface{})

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
	var ipv4addresses string
	var ipv6addresses string

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
		internetTests["IPv4 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp4")
		// internetTests["IPv4 UDP Connect ("+internetTarget+":53)"] = checkConnection(internetTarget, 53, "udp4")
	}
	if ipv6addresses != "" {
		internetTests["IPv6 Connect ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp6")
	}

	// send back formatted output
	return getOutput(data, options.HealthCheck)

}

func getTemplateCsf() string {
	cf, _ := config.ReadConfiguration()
	templatePath := ""
	if cf != nil {
		templatePath = cf.TemplatesDirectory
	}
	return filepath.Join(templatePath, "/", ".checksum")
}

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
func checkUlimit(data map[string]interface{}, difflimit int) string {
	var limit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	if (limit.Max - limit.Cur) <= uint64(difflimit) {
		return fmt.Sprintf("You may need to increase your file descriptor limit. %v/%v used", limit.Cur, limit.Max)
	} else {
		return "Pass"
	}
}

func mapToJson(data map[string]interface{}) string {
	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(json)
}

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

func lookup(domain, dnsServer string) (string, string) {
	var ipv4s []string
	var ipv6s []string

	resolver := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, network, fmt.Sprintf("%s:53", dnsServer))
		},
	}

	ips, err := resolver.LookupIPAddr(context.Background(), domain)
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
