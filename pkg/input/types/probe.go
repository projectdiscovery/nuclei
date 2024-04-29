package types

// InputLivenessProbe is an interface for probing the liveness of an input
type InputLivenessProbe interface {
	// ProbeURL probes the scheme for a URL. first HTTPS is tried
	ProbeURL(input string) (string, error)
	// Close closes the liveness probe
	Close() error
}
