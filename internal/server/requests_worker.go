package server

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
)

func (s *DASTServer) setupWorkers() {
	go s.tasksConsumer()
}

func (s *DASTServer) tasksConsumer() {
	for req := range s.fuzzRequests {
		parsedReq, err := parseRawRequest(req)
		if err != nil {
			gologger.Warning().Msgf("Could not parse raw request: %s\n", err)
			continue
		}

		inScope, err := s.scopeManager.Validate(parsedReq.URL.URL, "")
		if err != nil {
			gologger.Warning().Msgf("Could not validate scope: %s\n", err)
			continue
		}
		if !inScope {
			gologger.Warning().Msgf("Request is out of scope: %s %s\n", parsedReq.Request.Method, parsedReq.URL.String())
			continue
		}

		if s.deduplicator.isDuplicate(parsedReq) {
			gologger.Warning().Msgf("Duplicate request detected: %s %s\n", parsedReq.Request.Method, parsedReq.URL.String())
			continue
		}

		gologger.Verbose().Msgf("Fuzzing request: %s %s\n", parsedReq.Request.Method, parsedReq.URL.String())
		s.tasksPool.Go(func() {
			s.fuzzRequest(req)
		})
	}
}

func (s *DASTServer) fuzzRequest(req PostReuestsHandlerRequest) {
	results, err := runNucleiWithFuzzingInput(req, s.options.Templates)
	if err != nil {
		gologger.Warning().Msgf("Could not run nuclei: %s\n", err)
		return
	}

	for _, result := range results {
		if err := s.options.OutputWriter.Write(&result); err != nil {
			gologger.Error().Msgf("Could not write result: %s\n", err)
		}
	}
}

func parseRawRequest(req PostReuestsHandlerRequest) (*types.RequestResponse, error) {
	parsedReq, err := types.ParseRawRequestWithURL(req.RawHTTP, req.URL)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse raw HTTP")
	}
	return parsedReq, nil
}
