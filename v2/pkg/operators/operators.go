package operators

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
)

// Operators contains the operators that can be applied on protocols
type Operators struct {
	// Matchers contains the detection mechanism for the request to identify
	// whether the request was successful
	Matchers []*matchers.Matcher `yaml:"matchers"`
	// Extractors contains the extraction mechanism for the request to identify
	// and extract parts of the response.
	Extractors []*extractors.Extractor `yaml:"extractors"`
	// MatchersCondition is the condition of the matchers
	// whether to use AND or OR. Default is OR.
	MatchersCondition string `yaml:"matchers-condition"`
	// cached variables that may be used along with request.
	matchersCondition matchers.ConditionType
}

// GetMatchersCondition returns the condition for the matchers
func (r *Operators) GetMatchersCondition() matchers.ConditionType {
	return r.matchersCondition
}
