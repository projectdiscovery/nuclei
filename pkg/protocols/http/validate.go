package http

import "github.com/pkg/errors"

func (request *Request) validate() error {
	if request.Race && request.NeedsRequestCondition() {
		return errors.New("'race' and 'req-condition' can't be used together")
	}

	if request.Redirects && request.HostRedirects {
		return errors.New("'redirects' and 'host-redirects' can't be used together")
	}

	return nil
}
