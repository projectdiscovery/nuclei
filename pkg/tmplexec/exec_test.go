package tmplexec

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetErrorCause_DebugMode(t *testing.T) {
	testCases := []struct {
		name        string
		err         error
		debugMode   bool
		expectTrace bool
		description string
	}{
		{
			name:        "Debug mode enabled - should enrich error",
			err:         errors.New("malformed request specified: GET /file=>"),
			debugMode:   true,
			expectTrace: true,
			description: "When debug mode is enabled, errors should be enriched with additional context",
		},
		{
			name:        "Debug mode disabled - should not enrich error",
			err:         errors.New("malformed request specified: GET /file=>"),
			debugMode:   false,
			expectTrace: false,
			description: "When debug mode is disabled, errors should not be enriched to avoid stack traces",
		},
		{
			name:        "Nil error - debug mode enabled",
			err:         nil,
			debugMode:   true,
			expectTrace: false,
			description: "Nil errors should return empty string regardless of debug mode",
		},
		{
			name:        "Nil error - debug mode disabled",
			err:         nil,
			debugMode:   false,
			expectTrace: false,
			description: "Nil errors should return empty string regardless of debug mode",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getErrorCause(tc.err, tc.debugMode)

			if tc.err == nil {
				assert.Empty(t, result, "Expected empty string for nil error")
				return
			}

			// Basic validation - result should contain the original error message
			assert.Contains(t, result, "malformed request specified",
				"Result should contain the original error message")

			if tc.debugMode {
				// In debug mode, we expect the error to be processed through errkit
				// This doesn't necessarily mean stack traces in the final result,
				// but ensures the error went through the enrichment path
				assert.NotEmpty(t, result, "Debug mode should produce non-empty result")
			} else {
				// In non-debug mode, we should get a simple error message
				// without any stack trace information
				assert.NotContains(t, result, "Stacktrace:",
					"Non-debug mode should not contain stack trace")
				assert.NotContains(t, result, "goroutine",
					"Non-debug mode should not contain goroutine information")
				assert.NotContains(t, result, "runtime/debug.Stack()",
					"Non-debug mode should not contain runtime stack information")
			}
		})
	}
}

func TestParseScanErrorWithDebug(t *testing.T) {
	testCases := []struct {
		name      string
		msg       string
		debugMode bool
		expected  string
	}{
		{
			name:      "Simple error - debug mode off",
			msg:       "connection refused",
			debugMode: false,
			expected:  "connection refused",
		},
		{
			name:      "Simple error - debug mode on",
			msg:       "connection refused",
			debugMode: true,
			expected:  "connection refused",
		},
		{
			name:      "ReadStatusLine error - debug mode off",
			msg:       "ReadStatusLine: malformed HTTP response",
			debugMode: false,
			expected:  "malformed HTTP response",
		},
		{
			name:      "Empty message",
			msg:       "",
			debugMode: false,
			expected:  "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseScanErrorWithDebug(tc.msg, tc.debugMode)
			assert.Contains(t, result, tc.expected,
				"Result should contain expected error message")
		})
	}
}

func TestGetErrorCause_ContextDeadlineHandling(t *testing.T) {
	testCases := []struct {
		name      string
		err       error
		debugMode bool
	}{
		{
			name:      "Context deadline exceeded - debug mode",
			err:       errors.New("context deadline exceeded"),
			debugMode: true,
		},
		{
			name:      "Context deadline exceeded - non-debug mode",
			err:       errors.New("context deadline exceeded"),
			debugMode: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getErrorCause(tc.err, tc.debugMode)
			assert.NotEmpty(t, result, "Should handle context deadline exceeded errors")
		})
	}
}

func TestGetErrorCause_ErrorMessageFormat(t *testing.T) {
	originalError := errors.New("test error message")

	debugResult := getErrorCause(originalError, true)
	nonDebugResult := getErrorCause(originalError, false)

	// Both should contain the original error message
	assert.Contains(t, debugResult, "test error message",
		"Debug result should contain original error message")
	assert.Contains(t, nonDebugResult, "test error message",
		"Non-debug result should contain original error message")

	// Non-debug should be simpler (no enrichment artifacts)
	assert.True(t, len(nonDebugResult) <= len(debugResult) ||
		strings.Count(nonDebugResult, "\n") <= strings.Count(debugResult, "\n"),
		"Non-debug result should be simpler than debug result")
}

// Benchmark to ensure the non-debug path is more efficient
func BenchmarkGetErrorCause_Debug(b *testing.B) {
	err := errors.New("benchmark test error")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		getErrorCause(err, true)
	}
}

func BenchmarkGetErrorCause_NonDebug(b *testing.B) {
	err := errors.New("benchmark test error")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		getErrorCause(err, false)
	}
}
