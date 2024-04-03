package gojs

import (
	"github.com/dop251/goja"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	ErrInvalidFuncOpts = errorutil.NewWithFmt("invalid function options: %v")
	ErrNilRuntime      = errorutil.New("runtime is nil")
)

type FuncOpts struct {
	Name        string
	Signatures  []string
	Description string
	FuncDecl    interface{}
}

// valid checks if the function options are valid
func (f *FuncOpts) valid() bool {
	return f.Name != "" && f.FuncDecl != nil && len(f.Signatures) > 0 && f.Description != ""
}

// RegisterFunc registers a function with given name, signatures and description
func RegisterFuncWithSignature(runtime *goja.Runtime, opts FuncOpts) error {
	if runtime == nil {
		return ErrNilRuntime
	}
	if !opts.valid() {
		return ErrInvalidFuncOpts.Msgf("name: %s, signatures: %v, description: %s", opts.Name, opts.Signatures, opts.Description)
	}
	return runtime.Set(opts.Name, opts.FuncDecl)
}
