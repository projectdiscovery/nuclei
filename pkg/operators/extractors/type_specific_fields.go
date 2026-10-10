package extractors

import "fmt"

// typeSpecificField describes a field that only one extractor type honours,
// together with a predicate that reports whether the field was set.
type typeSpecificField struct {
	// name is the YAML/JSON key of the field, used in the error message.
	name string
	// set reports whether the template author supplied the field.
	set func(e *Extractor) bool
	// owner is the only extractor type whose implementation reads it.
	owner ExtractorType
}

// typeSpecificFields lists every field that is only read by a single
// extractor's implementation.
//
// Leaving one of these on a different extractor type is a no-op: the template
// still compiles and runs, and the extractor silently returns whatever its own
// type collects, which is indistinguishable from "nothing matched the target".
// A template author who writes `attribute` on a `json` extractor gets neither
// an error nor a warning, so the misconfiguration shows up only as a template
// that quietly under-reports findings. Rejecting the combination turns that
// silent false negative into a load-time error, the same way CaseInsensitive is
// already rejected outside kval extractors.
//
// `group` is deliberately absent even though ExtractRegex is its only reader.
// It is a no-op on other types in exactly the same way, but a survey of all
// 14,029 templates in nuclei-templates found 17 extractors that set `group` on
// a json or kval extractor, all of them published CVE detections such as
// CVE-2024-3848. Rejecting those would break real templates, so `group` stays
// silently ignored until those templates are corrected.
var typeSpecificFields = []typeSpecificField{
	{
		name:  "attribute",
		set:   func(e *Extractor) bool { return e.Attribute != "" },
		owner: XPathExtractor,
	},
}

// validateTypeSpecificFields returns an error for the first field that is set
// on an extractor type that never reads it.
func (e *Extractor) validateTypeSpecificFields() error {
	for _, field := range typeSpecificFields {
		if !field.set(e) || e.extractorType == field.owner {
			continue
		}
		return fmt.Errorf(
			"%s is supported only for '%s' extractors (not '%s')",
			field.name,
			field.owner,
			e.extractorType,
		)
	}
	return nil
}
