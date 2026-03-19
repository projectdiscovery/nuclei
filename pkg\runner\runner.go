package runner

// ... (existing imports and code)

// RunEnumeration sets up the input layer for awaiting
// and starts the execution
func (r *Runner) RunEnumeration() error {
	// ... existing code before template execution

	// Fix: Ensure secrets are pre-fetched BEFORE starting template execution
	// This was the bug - PreFetchSecrets was not guaranteed to complete
	// before templates started executing
	if r.executerOpts.AuthProvider != nil {
		if err := r.executerOpts.AuthProvider.PreFetchSecrets(); err != nil {
			gologger.Warning().Msgf("Could not pre-fetch secrets: %s\n", err)
		}
	}

	// ... rest of the execution
}
