package goexec

import "errors"

var (
	ErrMissingAuth             = errors.New("goexec auth is required")
	ErrMissingUsername         = errors.New("goexec username is required for this auth mode")
	ErrMultipleCredentialModes = errors.New("goexec auth selects multiple primary credential modes")
	ErrMissingTarget           = errors.New("goexec target is required")
	ErrMissingCommand          = errors.New("goexec command is required")
	ErrMissingExecutable       = errors.New("goexec executable is required")
	ErrUnsupportedModule       = errors.New("unsupported goexec module")
	ErrUnsupportedMethod       = errors.New("unsupported goexec method")
	ErrUnsupportedOutputMethod = errors.New("unsupported goexec output method")
	ErrNetworkPolicyDenied     = errors.New("target denied by network policy")
	ErrInvalidMethodArguments  = errors.New("invalid goexec method arguments")
	ErrDomainControllerDenied  = errors.New("domain controller denied by network policy")
	ErrProxyDenied             = errors.New("proxy denied by network policy")
	ErrEndpointDenied          = errors.New("endpoint denied by network policy")
)
