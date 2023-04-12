package http

import (
	"fmt"

	"github.com/pkg/errors"
)

func (request *Request) validate() error {
	fmt.Println("inside validate", request.Race)
	if request.Race && request.NeedsRequestCondition() {
		return errors.New("'race' and 'req-condition' can't be used together")
	}

	if request.Redirects && request.HostRedirects {
		return errors.New("'redirects' and 'host-redirects' can't be used together")
	}

	return nil
}
