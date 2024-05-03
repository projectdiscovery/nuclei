package errkit

import "encoding/json"

var (
	_ json.Marshaler  = &ErrorX{}
	_ JoinedError     = &ErrorX{}
	_ CauseError      = &ErrorX{}
	_ ComparableError = &ErrorX{}
	_ error           = &ErrorX{}
)

// below contains all interfaces that are implemented by ErrorX which
// makes it compatible with other error packages

// JoinedError is implemented by errors that are joined by Join
type JoinedError interface {
	// Unwrap returns the underlying error
	Unwrap() []error
}

// CauseError is implemented by errors that have a cause
type CauseError interface {
	// Cause return the original error that caused this without any wrapping
	Cause() error
}

// ComparableError is implemented by errors that can be compared
type ComparableError interface {
	// Is checks if current error contains given error
	Is(err error) bool
}
