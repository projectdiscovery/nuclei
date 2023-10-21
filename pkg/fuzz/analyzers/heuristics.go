package analyzers

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/common"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/common/compare"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/common/normalizer"
	"github.com/projectdiscovery/retryablehttp-go"
)

// HeuristicsAnalyzer performs heuristics based analysis of the request
//
// It compares true and false responses for a request and tries to
// find differences between them.
type HeuristicsAnalyzer struct{}

var _ Analyzer = &HeuristicsAnalyzer{}

// Analyze performs analysis of the request using heuristics
func (a *HeuristicsAnalyzer) Analyze(
	httpclient *retryablehttp.Client,
	input *AnalyzerInput,
) (*Analysis, error) {
	// Do a baseline request of the URL to get
	// the baseline true response. This also allows us to
	// test if the page content is dynamic or not.
	firstTrueBaseline, secondTrueBaseline, err := a.createRequestBaseline(
		httpclient,
		input.Request,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not get true request baseline")
	}

	// Check if the pages are identical. If so that means
	// there's no dynamic content on the page that we need to worry
	// about. if there's dynamic content, we need to handle it separately.
	if !strings.EqualFold(firstTrueBaseline.normalized, secondTrueBaseline.normalized) {
		// There's dynamic content on the page.
		// TODO: Use dynamic comparison logic like sqlmap to detect
		// and remove dynamic parts of the request.
		fmt.Printf("Dynamic content detected for %s\n", input.Request.URL.String())
		return nil, errors.New("dynamic content detected")
	}

	fmt.Printf("No dynamic content detected for %s\n", input.Request.URL.String())

	// Do a check to get the false response for the request.
	// This is done by modifying the component parameter
	// value to a random value that should not give any results.
	// This is done to get a false response for the request.
	falseResponse, err := a.getProbeNormalizedResponse(
		httpclient,
		input,
		common.RandString(6),
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not get false request baseline")
	}

	// Get the true and false payloads from payloads and do
	// request for both separately. This will allow us to compare
	// whether the application response is controllable using the
	// payload.
	truePayload := input.FinalArgs["true"].(string)
	falsePayload := input.FinalArgs["false"].(string)

	// Do a request for the true payload
	payloadTrueResponse, err := a.getProbeNormalizedResponse(
		httpclient,
		input,
		truePayload,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not get true payload response")
	}

	// Do a request for the false payload
	payloadFalseResponse, err := a.getProbeNormalizedResponse(
		httpclient,
		input,
		falsePayload,
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not get false payload response")
	}

	// Compare the true and false responses for the request.
	trueComparison := payloadTrueResponse.Compare(firstTrueBaseline)
	falseComparison := payloadFalseResponse.Compare(falseResponse)

	fmt.Printf("trueComparison: %v\n", trueComparison)
	fmt.Printf("falseComparison: %v\n", falseComparison)

	if trueComparison && falseComparison {
		fmt.Printf("payloadTrueResponse matches firstTrueBaseline\n")
		fmt.Printf("payloadFalseResponse Matches falseResponse\n")
		fmt.Printf("The response is controllable by the payload\n")
	} else {
		fmt.Printf("The response is not controllable by the payload\n")
	}
	return nil, nil
}

type responseContainer struct {
	normalized string
	response   *http.Response
}

func (r *responseContainer) Compare(other *responseContainer) bool {
	// TODO: Right now we do very simple string comparison.
	// Later based on the dynamicity of the payload, ideally we should
	// do a more complex comparison.
	return compare.CompareResponses(r.normalized, other.normalized)
}

// createRequestBaseline creates a request baseline for the request
// and returns the true response for the request by doing
// two requests.
func (a *HeuristicsAnalyzer) createRequestBaseline(
	httpclient *retryablehttp.Client,
	req *retryablehttp.Request,
) (*responseContainer, *responseContainer, error) {
	first, err := a.getNormalizedHTTPResponse(httpclient, req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get normalized response")
	}
	second, err := a.getNormalizedHTTPResponse(httpclient, req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get normalized response")
	}
	return first, second, nil
}

// getNormalizedHTTPResponse returns the normalized response for the request
func (a *HeuristicsAnalyzer) getNormalizedHTTPResponse(
	httpclient *retryablehttp.Client,
	req *retryablehttp.Request,
) (*responseContainer, error) {
	resp, err := httpclient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not do request")
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "could not read response body")
	}
	normalized, err := normalizer.DefaultNormalizer.Apply(string(data))
	if err != nil {
		return nil, errors.Wrap(err, "could not normalize response")
	}
	return &responseContainer{
		normalized: normalized,
		response:   resp,
	}, nil
}

// getProbeNormalizedResponse returns the normalized response for the request
// with the given value set for the component
func (a *HeuristicsAnalyzer) getProbeNormalizedResponse(
	httpclient *retryablehttp.Client,
	input *AnalyzerInput,
	value string,
) (*responseContainer, error) {
	err := input.Component.SetValue(input.Key, value)
	if err != nil {
		return nil, errors.Wrap(err, "could not set value for component")
	}
	falseRequest, err := input.Component.Rebuild()
	if err != nil {
		return nil, errors.Wrap(err, "could not rebuild request")
	}

	falseResponse, err := a.getNormalizedHTTPResponse(httpclient, falseRequest)
	if err != nil {
		return nil, errors.Wrap(err, "could not get response")
	}
	return falseResponse, nil
}
