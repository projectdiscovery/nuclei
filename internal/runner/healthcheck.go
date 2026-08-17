package runner

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

const defaultNetworkTimeout = 5 * time.Second

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
	ctx, cancel := context.WithTimeout(context.Background(), defaultNetworkTimeout)
	defer cancel()

	var d net.Dialer
	c4, err := d.DialContext(ctx, "tcp4", "scanme.sh:80")
	if err == nil && c4 != nil {
		_ = c4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv4 connectivity to scanme.sh:80 => %s\n", testResult)

	ctx2, cancel2 := context.WithTimeout(context.Background(), defaultNetworkTimeout)
	defer cancel2()
	c6, err := d.DialContext(ctx2, "tcp6", "scanme.sh:80")
	if err == nil && c6 != nil {
		_ = c6.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv6 connectivity to scanme.sh:80 => %s\n", testResult)

	ctx3, cancel3 := context.WithTimeout(context.Background(), defaultNetworkTimeout)
	defer cancel3()
	u4, err := d.DialContext(ctx3, "udp4", "scanme.sh:53")
	if err == nil && u4 != nil {
		_ = u4.Close()
	}
	testResult = "Ok"
	if err != nil {
		testResult = fmt.Sprintf("Ko (%s)", err)
	}
	fmt.Fprintf(&test, "IPv4 UDP connectivity to scanme.sh:53 => %s\n", testResult)

	return test.String()
}
