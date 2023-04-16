package interactsh

import (
	"regexp"
	"time"
)

var (
	defaultInteractionDuration = 60 * time.Second
	interactshURLMarkerRegex   = regexp.MustCompile(`{{interactsh-url(?:_[0-9]+){0,3}}}`)
)

const (
	stopAtFirstMatchAttribute = "stop-at-first-match"
	templateIdAttribute       = "template-id"

	defaultMaxInteractionsCount = 5000
)
