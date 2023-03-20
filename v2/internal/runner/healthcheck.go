package runner

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

// DoHealthCheck performs self-diagnostic checks
func DoHealthCheck(options *types.Options) string {

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

	//var test strings.Builder
	var testResult string
	var output string
	internetTarget := "scanme.sh"
	fileTests := data["files"].(map[string]interface{})
	internetTests := data["internet"].(map[string]interface{})

	// RW permissions on config file
	nucleiIgnorePath := config.GetIgnoreFilePath()
	cf, _ := config.ReadConfiguration()
	templatePath := ""
	if cf != nil {
		templatePath = cf.TemplatesDirectory
	}
	nucleiTemplatePath := filepath.Join(templatePath, "/", ".checksum")
	for _, filename := range []string{options.ConfigPath, nucleiIgnorePath, nucleiTemplatePath} {
		ok, err := fileutil.IsReadable(filename)
		if ok {
			testResult = "Pass"
		} else {
			testResult = "Fail"
		}
		if err != nil {
			testResult += fmt.Sprintf(" (%s)", err)
		}
		fileTests["Read: "+filename] = testResult
		ok, err = fileutil.IsWriteable(filename)
		if ok {
			testResult = "Pass"
		} else {
			testResult = "Fail"
		}
		if err != nil {
			testResult += fmt.Sprintf(" (%s)", err)
		}
		fileTests["Write: "+filename] = testResult
	}

	// Other Host information
	// ulimit
	// TODO: check how this operates on Windows
	var limit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	if (limit.Max - limit.Cur) <= 1000 {
		data["os"].(map[string]interface{})["ulimit"] = fmt.Sprintf("You may need to increase your file descriptor limit. %v/%v used", limit.Cur, limit.Max)
	}

	// Internet connectivity
	c4, err := net.Dial("tcp4", internetTarget+":80")
	if err == nil && c4 != nil {
		c4.Close()
	}
	testResult = "Pass"
	if err != nil {
		testResult = fmt.Sprintf("Fail (%s)", err)
	}
	internetTests["IPv4 Port 80"] = testResult

	c6, err := net.Dial("tcp6", internetTarget+":80")
	if err == nil && c6 != nil {
		c6.Close()
	}
	testResult = "Pass"
	if err != nil {
		testResult = fmt.Sprintf("Fail (%s)", err)
	}
	internetTests["IPv6 Port 80"] = testResult

	u4, err := net.Dial("udp4", internetTarget+":53")
	if err == nil && u4 != nil {
		u4.Close()
	}
	testResult = "Pass"
	if err != nil {
		testResult = fmt.Sprintf("Fail (%s)", err)
	}
	internetTests["IPv4 UDP Port 53"] = testResult

	// Internet DNS

	// Output format options
	// TODO: text table
	if options.HealthCheck == "json" {
		json, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			panic(err)
		}
		output = string(json)
	} else if options.HealthCheck == "md" || options.HealthCheck == "txt" || options.HealthCheck == "text" {
		output = mapToMarkdownTable(data)
	}

	return output
}

func mapToMarkdownTable(data map[string]interface{}) string {
	var test strings.Builder
	test.WriteString("| Test | Result | \n")
	test.WriteString("| --- | --- | \n")
	for key, value := range data {
		test.WriteString("| " + strings.ToUpper(key) + " | | \n")
		subMap, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		for subKey, subValue := range subMap {
			test.WriteString(("| " + subKey + "| " + fmt.Sprintf("%v", subValue) + " |\n"))
		}
	}
	return test.String()
}
