package core

import (
	"context"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

type EnumerateOption func(opts *protocols.ExecutorOptions)

func WithContext(ctx context.Context) EnumerateOption {
	return func(opts *protocols.ExecutorOptions) {
		opts.Ctx = ctx
	}
}
