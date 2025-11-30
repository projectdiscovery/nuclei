package protocolstate

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/env"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/projectdiscovery/utils/memguardian"
)

var (
	MaxThreadsOnLowMemory          = env.GetEnvOrDefault("MEMGUARDIAN_THREADS", 0)
	MaxBytesBufferAllocOnLowMemory = env.GetEnvOrDefault("MEMGUARDIAN_ALLOC", 0)
	memTimer                       *time.Ticker
	cancelFunc                     context.CancelFunc
	muGlobalChange                 sync.Mutex
)

func StartActiveMemGuardian(ctx context.Context) {
	muGlobalChange.Lock()
	defer muGlobalChange.Unlock()
	if memguardian.DefaultMemGuardian == nil || memTimer != nil {
		return
	}

	memTimer = time.NewTicker(memguardian.DefaultInterval)
	ctx, cancelFunc = context.WithCancel(ctx)

	ticker := memTimer
	go func(t *time.Ticker) {
		if t == nil {
			return
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if IsLowOnMemory() {
					_ = GlobalGuardBytesBufferAlloc()
				} else {
					GlobalRestoreBytesBufferAlloc()
				}
			}
		}
	}(ticker)
}

func StopActiveMemGuardian() {
	muGlobalChange.Lock()
	defer muGlobalChange.Unlock()

	if memguardian.DefaultMemGuardian == nil {
		return
	}

	if cancelFunc != nil {
		cancelFunc()
		cancelFunc = nil
	}
	if memTimer != nil {
		memTimer.Stop()
		memTimer = nil
	}
}

func IsLowOnMemory() bool {
	if memguardian.DefaultMemGuardian != nil && memguardian.DefaultMemGuardian.Warning.Load() {
		return true
	}
	return false
}

// GuardThreads on caller
func GuardThreadsOrDefault(current int) int {
	if MaxThreadsOnLowMemory > 0 {
		return MaxThreadsOnLowMemory
	}

	fraction := int(current / 5)
	if fraction > 0 {
		return fraction
	}

	return 1
}

// Global setting
func GlobalGuardBytesBufferAlloc() error {
	if !muGlobalChange.TryLock() {
		return nil
	}
	defer muGlobalChange.Unlock()

	// if current capacity was not reduced decrease it
	if MaxBytesBufferAllocOnLowMemory > 0 && httputil.DefaultBufferSize == httputil.GetPoolSize() {
		gologger.Debug().Msgf("reducing bytes.buffer pool size to: %d", MaxBytesBufferAllocOnLowMemory)
		delta := httputil.GetPoolSize() - int64(MaxBytesBufferAllocOnLowMemory)
		return httputil.ChangePoolSize(-delta)
	}

	return nil
}

// Global setting
func GlobalRestoreBytesBufferAlloc() {
	if !muGlobalChange.TryLock() {
		return
	}
	defer muGlobalChange.Unlock()

	if httputil.DefaultBufferSize != httputil.GetPoolSize() {
		delta := httputil.DefaultBufferSize - httputil.GetPoolSize()
		gologger.Debug().Msgf("restoring bytes.buffer pool size to: %d", httputil.DefaultBufferSize)
		_ = httputil.ChangePoolSize(delta)
	}
}
