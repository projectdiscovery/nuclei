package ssl

import (
	"crypto/tls"
	"fmt"

	ztls "github.com/zmap/zcrypto/tls"
)

var versions = map[string]uint16{
	"sslv3": ztls.VersionSSL30,
	"tls10": ztls.VersionTLS10,
	"tls11": ztls.VersionTLS11,
	"tls12": ztls.VersionTLS12,
	"tls13": tls.VersionTLS13,
}

func toVersion(item string) (uint16, error) {
	if version, ok := versions[item]; ok {
		return version, nil
	}
	return 0, fmt.Errorf("unsupported version: %s", item)
}
