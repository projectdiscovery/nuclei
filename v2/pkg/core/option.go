package core

import "context"

type EnumerationOptions struct {
	ctx context.Context
}

type EnumerateOption func(opts *EnumerationOptions)

func WithContext(ctx context.Context) EnumerateOption {
	return func(opts *EnumerationOptions) {
		opts.ctx = ctx
	}
}
