package runner

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	fileutil "github.com/projectdiscovery/utils/file"
)

// DoHealthCheck performs self-diagnostic checks
func DoHealthCheck(options *types.Options) string {
	// RW permissions on config file
	var test strings.Builder
	fmt.Fprintf(&test, "Version: %s\n", config.Version)
	fmt.Fprintf(&test, "Operating System: %s\n", runtime.GOOS)
	fmt.Fprintf(&test, "Architecture: %s\n", runtime.GOARCH)
	fmt.Fprintf(&test, "Go Version: %s\n", runtime.Version())
	fmt.Fprintf(&test, "Compiler: %s\n", runtime.Compiler)
	AppendDirectoryInfo(&test)

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
		fmt.Fprintf(&test, "File \"%s\" Read => %s\n", filename, testResult)
		ok, err = fileutil.IsWriteable(filename)
		if ok {
			testResult = "Ok"
		} else {
			testResult = "Ko"
		}
		if err != nil {
			testResult += fmt.Sprintf(" (%s)", err)
		}
		fmt.Fprintf(&test, "File \"%s\" Write => %s\n", filename, testResult)
	}
	c4, err := net.Dial("tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		_ = c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv4 connectivity to scanme.sh:80 => %s\n", testResult)
	c6, err := net.Dial("tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		_ = c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv6 connectivity to scanme.sh:80 => %s\n", testResult)
	u4, err := net.Dial("udp4", "scanme.sh:53")
	if err == nil && u4 != nil {
		_ = u4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv4 UDP connectivity to scanme.sh:53 => %s\n", testResult)

	appendPDCPHealthCheck(&test, (&pdcpauth.PDCPCredHandler{}).GetCreds, func(key, server, tool string) (*pdcpauth.PDCPCredentials, error) {
		return (&pdcpauth.PDCPCredHandler{}).ValidateAPIKey(key, server, tool)
	})

	return test.String()
}

// appendPDCPHealthCheck validates PDCP API connectivity when credentials are configured.
func appendPDCPHealthCheck(
	test *strings.Builder,
	getCreds func() (*pdcpauth.PDCPCredentials, error),
	validate func(key, server, tool string) (*pdcpauth.PDCPCredentials, error),
) {
	creds, err := getCreds()
	if err != nil {
		// Only check when an API key is configured.
		return
	}
	if creds == nil || creds.APIKey == "" {
		return
	}

	server := creds.Server
	if server == "" {
		server = pdcpauth.DefaultApiServer
	}

	validated, err := validate(creds.APIKey, server, config.BinaryName)
	if err != nil {
		fmt.Fprintf(test, "PDCP API (%s) => Ko (%s)\n", server, err)
		return
	}

	identity := validated.Email
	if validated.Username != "" {
		identity = "@" + validated.Username
	}
	fmt.Fprintf(test, "PDCP API (%s) => Ok (%s)\n", server, identity)
}
