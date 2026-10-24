package portscan

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		specs   []string
		want    []int
		wantErr bool
	}{
		{name: "single", specs: []string{"8080"}, want: []int{8080}},
		{name: "range", specs: []string{"80-82"}, want: []int{80, 81, 82}},
		{name: "mixed and dedup", specs: []string{"443", "80-82", "443", "81"}, want: []int{80, 81, 82, 443}},
		{name: "reversed range", specs: []string{"82-80"}, want: []int{80, 81, 82}},
		{name: "spaces", specs: []string{" 80 ", " 3000 - 3001 "}, want: []int{80, 3000, 3001}},
		{name: "comma list style", specs: []string{"22", "80", "443"}, want: []int{22, 80, 443}},
		{name: "invalid text", specs: []string{"http"}, wantErr: true},
		{name: "invalid range", specs: []string{"80-"}, wantErr: true},
		{name: "out of range", specs: []string{"70000"}, wantErr: true},
		{name: "zero port", specs: []string{"0"}, wantErr: true},
		{name: "huge range", specs: []string{"1-99999"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.specs)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePorts(%v) err = %v, wantErr %v", tt.specs, err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParsePorts(%v) = %v, want %v", tt.specs, got, tt.want)
			}
		})
	}
}
