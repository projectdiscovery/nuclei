package http

import "testing"

func TestBodyReadLimit(t *testing.T) {
	const twoMB = 2 * 1024 * 1024
	const twentyMB = 20 * 1024 * 1024
	const fiftyMB = 50 * 1024 * 1024

	tests := []struct {
		name             string
		templateMaxSize  int
		responseReadSize int
		want             int
	}{
		{name: "default", want: MaxBodyRead},
		{name: "template below default", templateMaxSize: 500, want: 500},
		{name: "template above default without global cap", templateMaxSize: twentyMB, want: twentyMB},
		{name: "global cap below default", responseReadSize: twoMB, want: twoMB},
		{name: "global cap above default", responseReadSize: fiftyMB, want: fiftyMB},
		{name: "template smaller than global cap", templateMaxSize: 500, responseReadSize: twoMB, want: 500},
		{name: "global cap smaller than template", templateMaxSize: twentyMB, responseReadSize: twoMB, want: twoMB},
		{name: "template below raised global cap", templateMaxSize: 500, responseReadSize: fiftyMB, want: 500},
		{name: "template between default and raised global cap", templateMaxSize: twentyMB, responseReadSize: fiftyMB, want: twentyMB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bodyReadLimit(tt.templateMaxSize, tt.responseReadSize)
			if got != tt.want {
				t.Fatalf("bodyReadLimit(%d, %d) = %d, want %d", tt.templateMaxSize, tt.responseReadSize, got, tt.want)
			}
		})
	}
}
