package httpclientpool

import "errors"

var (
	ErrRebuildURL = errors.New("could not rebuild request URL")
)
