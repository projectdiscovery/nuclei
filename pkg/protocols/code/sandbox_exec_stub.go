//go:build !linux

package code

import (
	"context"

	"github.com/projectdiscovery/gozero"
	gozerotypes "github.com/projectdiscovery/gozero/types"
)

func (request *Request) tryEvalSandboxed(_ context.Context, _ *gozero.Source) (*gozerotypes.Result, bool, error) {
	return nil, false, nil
}
