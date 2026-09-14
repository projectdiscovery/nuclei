//go:build integration
// +build integration

package integration_test

import "time"

// Keep duration assertions above the timer granularity of fast local sockets on Windows.
const integrationDurationObservationDelay = 10 * time.Millisecond
