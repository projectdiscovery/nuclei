package protocolstate

import (
	"github.com/projectdiscovery/utils/env"
	"github.com/projectdiscovery/utils/memguardian"
)

var (
	MaxThreadsOnLowMemory = env.GetEnvOrDefault("MEMGUARDIAN_THREADS", 0)
)

func IsLowOnMemory() bool {
	if memguardian.DefaultMemGuardian != nil && memguardian.DefaultMemGuardian.Warning.Load() {
		return true
	}

	return false
}

func GuardThreads(current int) int {
	if MaxThreadsOnLowMemory > 0 {
		return MaxThreadsOnLowMemory
	}

	fraction := int(current / 5)
	if fraction > 0 {
		return fraction
	}

	return 1
}
