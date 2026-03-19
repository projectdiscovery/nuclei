package runner

// RunEnumeration sets up the input layer for awaiting
// and starts the execution
func (r *Runner) RunEnumeration() error {
	// existing code...
	
	// The bug: PreFetchSecrets() might be called in a goroutine
	// or the auth initialization happens after templates start
	
	// The fix: ensure PreFetchSecrets() completes synchronously
	// before any templates execute
}
