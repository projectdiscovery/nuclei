// RunEnumeration sets up the input layer for awaiting
// and starts the execution
func (r *Runner) RunEnumeration() error {
	// ...
	
	// If secret file was provided, pre-fetch secrets first
	// BEFORE starting template execution
	if r.options.SecretsFile != "" {
		if err := r.executerOpts.AuthProvider.PreFetchSecrets(); err != nil {
			return err
		}
	}
	
	// ... rest of the execution
}
