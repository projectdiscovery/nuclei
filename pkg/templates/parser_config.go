package templates

import "regexp"

var (
	ReTemplateID = regexp.MustCompile(`^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$`)
)
