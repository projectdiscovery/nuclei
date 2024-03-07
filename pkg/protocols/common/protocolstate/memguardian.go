package protocolstate

import "github.com/projectdiscovery/utils/memguardian"

func IsLowOnMemory() bool {
	if memguardian.DefaultMemGuardian != nil && memguardian.DefaultMemGuardian.Warning.Load() {
		return true
	}

	return false
}
