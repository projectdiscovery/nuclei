package protocols

// Rule is an interface implemented by a protocol rule
type Rule interface {
	// Compile compiles the protocol request for further execution.
	Compile() error
	// Requests returns the total number of requests the rule will perform
	Requests() int64
}
