package writer

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
)

// WriteResult is a helper for writing results to the output
func WriteResult(data *output.InternalWrappedEvent, output output.Writer, progress progress.Progress, issuesClient *reporting.Client) bool {
	// Handle the case where no result found for the template.
	// In this case, we just show misc information about the failed
	// match for the template.
	if data.OperatorsResult == nil {
		return false
	}
	var matched bool
	for _, result := range data.Results {
		if err := output.Write(result); err != nil {
			gologger.Warning().Msgf("Could not write output event: %s\n", err)
		}
		if !matched {
			matched = true
		}
		progress.IncrementMatched()

		if issuesClient != nil {
			if err := issuesClient.CreateIssue(result); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
	}
	return matched
}
