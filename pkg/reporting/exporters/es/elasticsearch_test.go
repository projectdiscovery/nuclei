package es

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestOptionsValidation(t *testing.T) {
	validate := validator.New()

	tests := []struct {
		name    string
		opts    Options
		wantErr bool
	}{
		{
			name: "host only",
			opts: Options{
				Host:      "elasticsearch.local",
				Port:      9200,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: false,
		},
		{
			name: "ip only",
			opts: Options{
				IP:        "192.168.1.1",
				Port:      9200,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: false,
		},
		{
			name: "both host and ip",
			opts: Options{
				Host:      "elasticsearch.local",
				IP:        "192.168.1.1",
				Port:      9200,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: false,
		},
		{
			name:    "neither host nor ip",
			opts: Options{
				Port:      9200,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: true,
		},
		{
			name: "ip with invalid format",
			opts: Options{
				IP:        "not-an-ip",
				Port:      9200,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: true,
		},
		{
			name: "ipv6 address",
			opts: Options{
				IP:        "::1",
				Port:      9200,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: false,
		},
		{
			name: "missing username",
			opts: Options{
				Host:      "elasticsearch.local",
				Port:      9200,
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: true,
		},
		{
			name: "missing password",
			opts: Options{
				Host:      "elasticsearch.local",
				Port:      9200,
				Username:  "admin",
				IndexName: "nuclei",
			},
			wantErr: true,
		},
		{
			name: "missing index name",
			opts: Options{
				Host:     "elasticsearch.local",
				Port:     9200,
				Username: "admin",
				Password: "secret",
			},
			wantErr: true,
		},
		{
			name: "port out of range",
			opts: Options{
				Host:      "elasticsearch.local",
				Port:      70000,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: true,
		},
		{
			name: "zero port is valid",
			opts: Options{
				Host:      "elasticsearch.local",
				Port:      0,
				Username:  "admin",
				Password:  "secret",
				IndexName: "nuclei",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate.Struct(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("validate.Struct() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
