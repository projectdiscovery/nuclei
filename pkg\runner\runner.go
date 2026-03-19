// In RunEnumeration, before templates execute:

// Pre-fetch secrets synchronously before starting scan
// Fix for: https://github.com/projectdiscovery/nuclei/issues/6592
if r.executerOpts.AuthProvider != nil {
    if err := r.executerOpts.AuthProvider.PreFetchSecrets(); err != nil {
        gologger.Warning().Msgf("Could not pre-fetch secrets: %s\n", err)
    }
}
