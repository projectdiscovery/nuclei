package httpclientpool

import "time"

// WithCustomTimeout is a configuration for custom timeout
type WithCustomTimeout struct {
	Timeout time.Duration
}
