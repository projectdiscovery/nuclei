package authprovider

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/utils/errkit"
)

// NewInlineAuthProvider creates a new auth provider from an Authx struct that
// was parsed directly from a config or template profile file's "secrets" block.
// This avoids writing secrets to a temporary file and uses the Authx struct
// directly, as opposed to NewFileAuthProvider which reads from a file on disk.
func NewInlineAuthProvider(store *authx.Authx, callback authx.LazyFetchSecret) (AuthProvider, error) {
	if store == nil {
		return nil, errkit.New("store is required")
	}
	if len(store.Secrets) == 0 && len(store.Dynamic) == 0 {
		return nil, ErrNoSecrets
	}
	if len(store.Dynamic) > 0 && callback == nil {
		return nil, errkit.New("lazy fetch callback is required for dynamic secrets")
	}
	for _, secret := range store.Secrets {
		if err := secret.Validate(); err != nil {
			errorErr := errkit.FromError(err)
			errorErr.Msgf("invalid inline secret")
			return nil, errorErr
		}
	}
	for i, dynamic := range store.Dynamic {
		if err := dynamic.Validate(); err != nil {
			errorErr := errkit.FromError(err)
			errorErr.Msgf("invalid inline dynamic secret")
			return nil, errorErr
		}
		dynamic.SetLazyFetchCallback(callback)
		store.Dynamic[i] = dynamic
	}
	f := &FileAuthProvider{Path: "", store: store}
	f.init()
	return f, nil
}
