package nucleierr

import (
	"strings"

	"github.com/projectdiscovery/utils/errkit"
)

var (
	// ErrTemplateLogic are errors that occured due to missing variable or something similar in template logic
	// so this is more of a virtual error that is expected due to template logic
	ErrTemplateLogic = errkit.NewPrimitiveErrKind("TemplateLogic", "Error expected due to template logic", isTemplateLogicKind)
)

// isTemplateLogicKind checks if an error is of template logic kind
func isTemplateLogicKind(err *errkit.ErrorX) bool {
	if err == nil || err.Cause() == nil {
		return false
	}
	v := err.Cause().Error()
	switch {
	case strings.Contains(v, "timeout annotation deadline exceeded"):
		return true
	case strings.Contains(v, "stop execution due to unresolved variables"):
		return true
	}
	return false
}
