package interactsh

import (
	"errors"
	"regexp"
	"time"
)

var (
	defaultInteractionDuration = 60 * time.Second
	interactshURLMarkerRegex   = regexp.MustCompile(`{{interactsh-url(?:_[0-9]+){0,3}}}`)

	ErrInteractshClientNotInitialized = errors.New("interactsh client not initialized")
)

const (
	stopAtFirstMatchAttribute = "stop-at-first-match"
	templateIdAttribute       = "template-id"

	defaultMaxInteractionsCount = 5000
)
