package interactsh

import (
	"errors"
	"time"
)

var (
	defaultInteractionDuration = 60 * time.Second

	ErrInteractshClientNotInitialized = errors.New("interactsh client not initialized")
)

const (
	stopAtFirstMatchAttribute   = "stop-at-first-match"
	templateIdAttribute         = "template-id"
	defaultMaxInteractionsCount = 5000
)
