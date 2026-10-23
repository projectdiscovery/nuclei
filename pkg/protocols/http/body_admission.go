package http

import (
	"context"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/memguardian"
	"golang.org/x/sync/semaphore"
)

const (
	largeBodyThreshold           = 1 << 20
	largeBodyMemoryAmplification = 64
)

type bodyAdmission struct {
	limit int64
	slots *semaphore.Weighted
}

var (
	sharedBodyAdmission     *bodyAdmission
	sharedBodyAdmissionOnce sync.Once
	sharedFlowAdmission     *bodyAdmission
	sharedFlowAdmissionOnce sync.Once
)

func newBodyAdmission(totalMemory uint64) *bodyAdmission {
	limit := int64(totalMemory / largeBodyMemoryAmplification)
	if limit < largeBodyThreshold {
		limit = largeBodyThreshold
	}
	return &bodyAdmission{limit: limit, slots: semaphore.NewWeighted(limit)}
}

func systemBodyAdmission() *bodyAdmission {
	info, err := memguardian.GetSysInfo()
	if err != nil {
		gologger.Warning().Msgf("could not read memory limit for large HTTP body admission: %s", err)
		return newBodyAdmission(4 << 30)
	}
	return newBodyAdmission(info.TotalRam())
}

func bodySize(req *generatedRequest) int64 {
	if req.rawRequest != nil {
		return int64(len(req.rawRequest.Data))
	}
	if req.request != nil {
		return req.request.ContentLength
	}
	return 0
}

func (a *bodyAdmission) acquire(ctx context.Context, size int64) (func(), error) {
	if size < largeBodyThreshold {
		return func() {}, nil
	}
	weight := min(size, a.limit)
	if err := a.slots.Acquire(ctx, weight); err != nil {
		return nil, err
	}
	return func() { a.slots.Release(weight) }, nil
}

func admitLargeBody(ctx context.Context, req *generatedRequest) (func(), error) {
	size := bodySize(req)
	return admitBodySize(ctx, size)
}

func admitBodySize(ctx context.Context, size int64) (func(), error) {
	if size < largeBodyThreshold {
		return func() {}, nil
	}
	sharedBodyAdmissionOnce.Do(func() {
		sharedBodyAdmission = systemBodyAdmission()
	})
	return sharedBodyAdmission.acquire(ctx, size)
}

// AdmitDeclaredBody bounds Flow executions before a declared large body is built.
func AdmitDeclaredBody(ctx context.Context, size int64) (func(), error) {
	if size < largeBodyThreshold {
		return func() {}, nil
	}
	sharedFlowAdmissionOnce.Do(func() {
		sharedFlowAdmission = systemBodyAdmission()
	})
	return sharedFlowAdmission.acquire(ctx, size)
}
