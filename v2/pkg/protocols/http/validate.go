package http

import "github.com/pkg/errors"

func (request *Request) validate() error {
	if request.Race && request.ReqCondition {
		return errors.New("race and req-condition can't be used together")
	}

	return nil
}
