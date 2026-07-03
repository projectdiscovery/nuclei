package portutil

import (
	"net"
	"strconv"

	"github.com/projectdiscovery/utils/errkit"
)

// serviceFallback covers well-known TCP services that Go's net.LookupPort
// may not resolve on all platforms (e.g., Windows lacks mysql).
var serviceFallback = map[string]int{
	"mysql":         3306,
	"postgres":      5432,
	"redis":         6379,
	"mongodb":       27017,
	"mssql":         1433,
	"rdp":           3389,
	"vnc":           5900,
	"memcached":     11211,
	"elasticsearch": 9200,
	"mqtt":          1883,
	"amqp":          5672,
}

// ResolvePort converts a port string (numeric or IANA service name) to a validated numeric port string.
func ResolvePort(port string) (string, error) {
	if port == "" {
		return "", errkit.New("empty port")
	}
	if portInt, err := strconv.Atoi(port); err == nil {
		if portInt < 1 || portInt > 65535 {
			return "", errkit.Newf("port %d is not in valid range", portInt)
		}
		return port, nil
	}
	if portInt, err := net.LookupPort("tcp", port); err == nil {
		return strconv.Itoa(portInt), nil
	}
	if portInt, ok := serviceFallback[port]; ok {
		return strconv.Itoa(portInt), nil
	}
	return "", errkit.Newf("unknown service name '%s'", port)
}
