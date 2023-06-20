package utils

import (
	"sync"

	iputil "github.com/projectdiscovery/utils/ip"
)

var (
	publicIP string
	getOnce  sync.Once
)

// todo: move to dsl package to avoid execution if not necessary
// GetPublicIp of the host
func GetPublicIP() string {
	getOnce.Do(func() {
		publicIP, _ = iputil.WhatsMyIP()
	})
	return publicIP
}
