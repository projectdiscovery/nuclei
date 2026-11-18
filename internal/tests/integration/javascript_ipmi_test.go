//go:build integration
// +build integration

package integration_test

import (
	"fmt"
	"net"
	"time"

	"github.com/ory/dockertest/v3"
)

// ipmiSimSetup runs OpenIPMI's BMC simulator with an anonymous user,
// ADMIN/ADMIN and root/calvin, and cipher suite 0 enabled.
const ipmiSimSetup = `apt-get update -qq && apt-get install -y -qq --no-install-recommends openipmi >/dev/null && mkdir -p /etc/ipmi && cat > /etc/ipmi/lan.conf <<'EOF'
name "bmc"
set_working_mc 0x20
  startlan 1
    addr 0.0.0.0 623
    priv_limit admin
    allowed_auths_callback none md2 md5 straight
    allowed_auths_user none md2 md5 straight
    allowed_auths_operator none md2 md5 straight
    allowed_auths_admin none md2 md5 straight
    guid a123456789abcdefa123456789abcdef
  endlan
  user 1 true  ""      ""       user  10 none md2 md5 straight
  user 2 true  "ADMIN" "ADMIN"  admin 10 none md2 md5 straight
  user 3 true  "root"  "calvin" admin 10 none md2 md5 straight
EOF
printf 'mc_setbmc 0x20\nmc_add 0x20 0 no-device-sdrs 0x23 9 8 0x9f 0x1291 0xf02 persist_sdr\nmc_enable 0x20\n' > /etc/ipmi/emu.cmd
exec ipmi_sim -c /etc/ipmi/lan.conf -f /etc/ipmi/emu.cmd -n`

type javascriptIPMI struct{}

func (j *javascriptIPMI) Execute(filePath string) error {
	pool, err := dockertest.NewPool("")
	if err != nil {
		return fmt.Errorf("could not create docker pool: %w", err)
	}
	if err := pool.Client.Ping(); err != nil {
		return fmt.Errorf("could not connect to Docker: %w", err)
	}
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "debian",
		Tag:          "bookworm-slim",
		Platform:     "linux/amd64",
		Cmd:          []string{"sh", "-c", ipmiSimSetup},
		ExposedPorts: []string{"623/udp"},
	})
	if err != nil {
		return fmt.Errorf("could not start ipmi simulator: %w", err)
	}
	defer purge(pool, resource)

	address := net.JoinHostPort("127.0.0.1", resource.GetPort("623/udp"))
	if err := waitForServiceCheck(address, 3*time.Minute, rmcpPingCheck); err != nil {
		return err
	}
	results, err := runSignedNucleiTemplateAndGetResults(filePath, address, debug)
	if err != nil {
		return err
	}
	return expectResultsCount(results, 1)
}

// rmcpPingCheck waits for an answer to an RMCP presence ping, since the
// port is udp and cannot be probed with a connect.
func rmcpPingCheck(address string) error {
	conn, err := net.Dial("udp", address)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte{0x06, 0x00, 0xff, 0x06, 0x00, 0x00, 0x11, 0xbe, 0x80, 0x00, 0x00, 0x00}); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 64)
	n, err := conn.Read(reply)
	if err != nil {
		return err
	}
	if n < 9 || reply[8] != 0x40 {
		return fmt.Errorf("unexpected rmcp reply")
	}
	return nil
}
