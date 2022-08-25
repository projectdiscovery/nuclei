package runner

import (
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// DoHealthCheck performs self-diagnostic checks
func DoHealthCheck(options *types.Options) string {
	// RW permissions on config file
	cfgFilePath, _ := goflags.GetConfigFilePath()
	var test strings.Builder
	test.WriteString(fmt.Sprintf("Version: %s\n", config.Version))
	test.WriteString(fmt.Sprintf("Operative System: %s\n", runtime.GOOS))
	test.WriteString(fmt.Sprintf("Architecture: %s\n", runtime.GOARCH))
	test.WriteString(fmt.Sprintf("Go Version: %s\n", runtime.Version()))
	test.WriteString(fmt.Sprintf("Compiler: %s\n", runtime.Compiler))

	var testResult string

	nucleiIgnorePath := config.GetIgnoreFilePath()
	cf, _ := config.ReadConfiguration()
	templatePath := ""
	if cf != nil {
		templatePath = cf.TemplatesDirectory
	}
	nucleiTemplatePath := filepath.Join(templatePath, "/", ".checksum")
	for _, filename := range []string{cfgFilePath, nucleiIgnorePath, nucleiTemplatePath} {
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
