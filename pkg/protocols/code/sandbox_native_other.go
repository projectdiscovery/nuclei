//go:build !linux && !darwin

package code

import (
	"context"
	"fmt"
	"runtime"

	"github.com/projectdiscovery/gozero"
	gozerotypes "github.com/projectdiscovery/gozero/types"
)

func (request *Request) evalNative(_ context.Context, _ *gozero.Source) (*gozerotypes.Result, error) {
	return nil, fmt.Errorf("%w: no native sandbox on %s", errNativeSandboxUnavailable, runtime.GOOS)
}
