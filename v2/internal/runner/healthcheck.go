package runner

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

// DoHealthCheck performs self-diagnostic checks
func DoHealthCheck(options *types.Options) string {
	// RW permissions on config file
	var test strings.Builder
	test.WriteString(fmt.Sprintf("Version: %s\n", config.Version))
	test.WriteString(fmt.Sprintf("Operating System: %s\n", runtime.GOOS))
	test.WriteString(fmt.Sprintf("Architecture: %s\n", runtime.GOARCH))
	test.WriteString(fmt.Sprintf("Go Version: %s\n", runtime.Version()))
	test.WriteString(fmt.Sprintf("Compiler: %s\n", runtime.Compiler))

	var testResult string
	cfg := config.DefaultConfig
	for _, filename := range []string{cfg.GetFlagsConfigFilePath(), cfg.GetIgnoreFilePath(), cfg.GetChecksumFilePath()} {
		ok, err := fileutil.IsReadable(filename)
		if ok {
			testResult = "Ok"
		} else {
			testResult = "Ko"
		}
		if err != nil {
			testResult += fmt.Sprintf(" (%s)", err)
		}
		test.WriteString(fmt.Sprintf("File \"%s\" Read => %s\n", filename, testResult))
		ok, err = fileutil.IsWriteable(filename)
		if ok {
			testResult = "Ok"
		} else {
			testResult = "Ko"
		}
		if err != nil {
			testResult += fmt.Sprintf(" (%s)", err)
		}
		test.WriteString(fmt.Sprintf("File \"%s\" Write => %s\n", filename, testResult))
	}
	c4, err := net.Dial("tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv4 connectivity to scanme.sh:80 => %s\n", testResult))
	c6, err := net.Dial("tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv6 connectivity to scanme.sh:80 => %s\n", testResult))
	u4, err := net.Dial("udp4", "scanme.sh:53")
	if err == nil && u4 != nil {
		u4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	test.WriteString(fmt.Sprintf("IPv4 UDP connectivity to scanme.sh:53 => %s\n", testResult))

	return test.String()
}
