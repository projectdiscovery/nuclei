package server

import (
	"context"
	"net/url"
	"path"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/server/scope"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
)

func (s *DASTServer) consumeTaskRequest(req PostRequestsHandlerRequest) {
	defer s.endpointsInQueue.Add(-1)

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		gologger.Warning().Msgf("Could not parse url: %s\n", err)
		return
	}

	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		gologger.Warning().Msgf("Invalid scheme: %s\n", parsedURL.Scheme)
		return
	}

	// Check filenames and don't allow non-interesting files
	extension := path.Base(parsedURL.Path)
	if extension != "/" && extension != "" && scope.IsUninterestingPath(extension) {
		gologger.Warning().Msgf("Uninteresting path: %s\n", parsedURL.Path)
		return
	}

	inScope, err := s.scopeManager.Validate(parsedURL)
	if err != nil {
		gologger.Warning().Msgf("Could not validate scope: %s\n", err)
		return
	}
	if !inScope {
		gologger.Warning().Msgf("Request is out of scope: %s\n", parsedURL.String())
		return
	}

	gologger.Verbose().Msgf("Fuzzing request: %s\n", parsedURL.String())

	s.endpointsBeingTested.Add(1)
	defer s.endpointsBeingTested.Add(-1)

	// Fuzz the request finally
	if s.nucleiExecutor != nil && req.RawRequest != "" {
		parsedReq, err := types.ParseRawRequestWithURL(req.RawRequest, req.URL)
		if err != nil {
			gologger.Warning().Msgf("Could not parse raw request: %s\n", err)
			return
		}

		if s.deduplicator.isDuplicate(parsedReq) {
			gologger.Warning().Msgf("Duplicate request detected: %s %s\n", parsedReq.Request.Method, parsedReq.URL.String())
			return
		}

		err = s.nucleiExecutor.ExecuteScan(req)
		if err != nil {
			gologger.Warning().Msgf("Could not run nuclei: %s\n", err)
			return
		}
	} else if s.passiveNuclei != nil && req.RawResponse != "" {
		var reqRespBuilder strings.Builder
		reqRespBuilder.WriteString(req.RawRequest)
		reqRespBuilder.WriteString("\n\n")
		reqRespBuilder.WriteString(req.RawResponse)

		results, err := s.passiveNuclei.Execute(context.Background(), reqRespBuilder.String(), req.URL)
		if err != nil {
			gologger.Warning().Msgf("Could not run nuclei: %s\n", err)
			return
		}
		for _, result := range results {
			if err := s.options.OutputWriter.Write(result); err != nil {
				gologger.Warning().Msgf("Could not write result: %s\n", err)
			}
		}
	}
}
