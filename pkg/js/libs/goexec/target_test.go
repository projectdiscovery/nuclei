package goexec

import "testing"

func TestNormalizeTargetPreservesBracketedIPv6WithPort(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{
			name:   "bracketed IPv6 with port",
			target: "[2001:db8::10]:445",
			want:   "[2001:db8::10]:445",
		},
		{
			name:   "URL with bracketed IPv6 and port",
			target: "smb://[2001:db8::10]:445/share",
			want:   "[2001:db8::10]:445",
		},
		{
			name:   "URL with bracketed IPv6 and no port",
			target: "smb://[2001:db8::10]/share",
			want:   "2001:db8::10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeTarget(tt.target)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
