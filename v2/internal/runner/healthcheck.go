package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

// DoHealthCheck performs self-diagnostic checks
func DoHealthCheck(options *types.Options) string {
	// Statics
	internetTarget := "scanme.sh"
	ulimitdiff := 1000

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

	// File permissions
	for _, filename := range []string{options.ConfigPath, config.GetIgnoreFilePath(), getTemplateCsf()} {
		fileTests["Read: "+filename] = checkFilePermissions(filename, "read")
		fileTests["Write: "+filename] = checkFilePermissions(filename, "write")
	}

	// Other Host information
	if runtime.GOOS != "windows" {
		// LINUX/UNIX Systems
		data["os"].(map[string]interface{})["ulimit"] = checkUlimit(data, ulimitdiff)
	} else {
		// Windows Systems
	}

	// Internet connectivity
	internetTests["IPv4 ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp4")
	internetTests["IPv6 ("+internetTarget+":80)"] = checkConnection(internetTarget, 80, "tcp6")
	internetTests["IPv4 UDP ("+internetTarget+":53)"] = checkConnection(internetTarget, 53, "udp4")

	// Internet DNS

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
	conn, err := net.Dial(protocol, host+":"+strconv.Itoa(port))
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
