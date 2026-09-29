package writer

import (
	stderrors "errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
)

// WriteResult is a helper for writing results to the output
func WriteResult(data *output.InternalWrappedEvent, out output.Writer, progress progress.Progress, issuesClient reporting.Client) bool {
	// Handle the case where no result found for the template.
	// In this case, we just show misc information about the failed
	// match for the template.
	if !data.HasOperatorResult() {
		return false
	}
	var matched bool
	for _, result := range data.Results {
		var suppressed bool
		if err := out.Write(result); err != nil {
			if stderrors.Is(err, output.ErrHoneypotSuppressed) {
				suppressed = true
			} else {
				gologger.Warning().Msgf("Could not write output event: %s\n", err)
			}
		}

		// Only create issues when the result was not suppressed.
		if issuesClient != nil && !suppressed {
			if err := issuesClient.CreateIssue(result); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
		if !matched {
			matched = true
		}
		if !suppressed {
			progress.IncrementMatched()
		}
	}
	return matched
}
