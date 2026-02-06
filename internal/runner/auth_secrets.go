package runner

import (
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// PrefetchAuthSecrets resolves secret-file auth before template execution.
// - logger is used for start/end/error messages.
// - provider is the auth provider to prefetch.
// - options supplies the secret-file list for logging and guard checks.
func PrefetchAuthSecrets(logger *gologger.Logger, provider authprovider.AuthProvider, options *types.Options) error {
	if provider == nil || options == nil || len(options.SecretsFile) == 0 {
		return nil
	}
	if logger == nil {
		logger = gologger.DefaultLogger
	}

	logger.Info().Msgf("Secret-file auth: prefetch starting for %d file(s)", len(options.SecretsFile))
	start := time.Now()
	if err := provider.PreFetchSecrets(); err != nil {
		logger.Error().Msgf("Secret-file auth: prefetch failed: %s", err)
		return errors.Wrap(err, "secret-file auth prefetch failed")
	}
	logger.Info().Msgf("Secret-file auth: prefetch completed in %s", time.Since(start))
	return nil
}
