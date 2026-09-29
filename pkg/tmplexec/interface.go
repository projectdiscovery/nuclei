package tmplexec

import (
	"errors"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/generic"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/multiproto"
	"github.com/projectdiscovery/utils/errkit"
)

var (
	_ TemplateEngine = &generic.Generic{}
	_ TemplateEngine = &flow.FlowExecutor{}
	_ TemplateEngine = &multiproto.MultiProtocol{}
)

// TemplateEngine is a template executor with different functionality
// Ex:
// 1. generic => executes all protocol requests one after another (Done)
// 2. flow  => executes protocol requests based on how they are defined in flow (Done)
// 3. multiprotocol => executes multiple protocols in parallel (Done)
type TemplateEngine interface {
	// Note: below methods only need to implement extra / engine specific functionality
	// basic request compilation , callbacks , cli output callback etc are handled by `TemplateExecuter` and no need to do it again
	// Extra Compilation (if any)
	Compile() error

	// ExecuteWithResults executes the template and returns results
	ExecuteWithResults(ctx *scan.ScanContext) error

	// Name returns name of template engine
	Name() string
}

var (
	// A temporary fix to remove errKind from error message
	// this is because errkit is not used everywhere yet
	reNoKind = regexp.MustCompile(`([\[][^][]+[\]]|errKind=[^ ]+) `)
)

// parseScanError parses given scan error and only returning the cause
// instead of inefficient one
func parseScanError(msg string) string {
	if msg == "" {
		return ""
	}
	if strings.HasPrefix(msg, "ReadStatusLine:") {
		// last index is actual error (from rawhttp)
		parts := strings.Split(msg, ":")
		msg = strings.TrimSpace(parts[len(parts)-1])
	}
	if strings.Contains(msg, "read ") {
		// same here
		parts := strings.Split(msg, ":")
		msg = strings.TrimSpace(parts[len(parts)-1])
	}
	e := errkit.FromError(errors.New(msg))
	for _, err := range e.Errors() {
		if err != nil && strings.Contains(err.Error(), "context deadline exceeded") {
			continue
		}
		msg = reNoKind.ReplaceAllString(err.Error(), "")
		return msg
	}
	wrapped := errkit.Append(errkit.New("failed to get error cause"), e).Error()
	return reNoKind.ReplaceAllString(wrapped, "")
}
