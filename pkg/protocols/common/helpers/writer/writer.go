package writer

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
)

// WriteResult is a helper for writing results to the output
func WriteResult(data *output.InternalWrappedEvent, outputs output.Writer, progress progress.Progress, issuesClient reporting.Client) bool {
	// Handle the case where no result found for the template.
	// In this case, we just show misc information about the failed
	// match for the template.
	if !data.HasOperatorResult() {
		return false
	}
	var matched bool
	steps := make([]output.Steps, 0)
	if types, ok := data.InternalEvent["type"]; ok {
		switch types.(string) {
		case "dns":
			request, request_ok := data.InternalEvent["request"]
			response, response_ok := data.InternalEvent["raw"]
			if request_ok && response_ok {
				steps = append(steps, output.Steps{Request: fmt.Sprintf("%v", request), Response: fmt.Sprintf("%v", response)})
			}
		case "http":
			index := 0
			for {
				index = index + 1
				key := fmt.Sprintf("http_%d", index)
				request, request_ok := data.InternalEvent[fmt.Sprintf("%s_request", key)]
				response, response_ok := data.InternalEvent[fmt.Sprintf("%s_response", key)]
				if !request_ok || !response_ok {
					break
				}
				steps = append(steps, output.Steps{Request: request.(string), Response: response.(string)})
			}
		default:

		}
	}
	for _, result := range data.Results {
		result.Steps = steps
		if issuesClient != nil {
			if err := issuesClient.CreateIssue(result); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
		if err := outputs.Write(result); err != nil {
			gologger.Warning().Msgf("Could not write output event: %s\n", err)
		}
		if !matched {
			matched = true
		}
		progress.IncrementMatched()
	}
	return matched
}
