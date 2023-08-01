package aws

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

func TestCatalog_GetTemplatePath(t *testing.T) {
	type args struct {
		target string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			"get all ssl files",
			args{
				target: "ssl",
			},
			[]string{
				"ssl/deprecated-tls.yaml",
				"ssl/detect-ssl-issuer.yaml",
				"ssl/expired-ssl.yaml",
				"ssl/mismatched-ssl.yaml",
			},
			false,
		},
		{
			"get all ssl files with wildcard",
			args{
				target: "ssl*",
			},
			[]string{
				"ssl/deprecated-tls.yaml",
				"ssl/detect-ssl-issuer.yaml",
				"ssl/expired-ssl.yaml",
				"ssl/mismatched-ssl.yaml",
			},
			false,
		},
		{
			"non-matching target",
			args{
				target: "I-DONT-EXIST",
			},
			[]string{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewCatalog("bucket", withMockS3Service())
			got, err := c.GetTemplatePath(tt.args.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTemplatePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(tt.want) > 0 && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetTemplatePath() got = %v, want %v", got, tt.want)
			}

			if len(tt.want) == 0 && len(got) > 0 {
				t.Errorf("GetTemplatePath() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCatalog_GetTemplatesPath(t *testing.T) {
	tmp := newMockS3Service()
	keys, _ := tmp.getAllKeys()

	type args struct {
		definitions []string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			"without definitions",
			args{
				definitions: nil,
			},
			keys,
			false,
		},
		{
			"with definitions",
			args{
				definitions: []string{"ssl/deprecated-tls.yaml"},
			},
			keys,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewCatalog("bucket", withMockS3Service())
			got, got1 := c.GetTemplatesPath(tt.args.definitions)

			if got1 != nil {
				val, exists := got1["aws"]
				if exists && !tt.wantErr {
					t.Errorf("GetTemplatesPath() error = %v, wantErr %v", val, tt.wantErr)
				}

				if !exists && len(got1) > 0 {
					t.Errorf("GetTemplatesPath() should only return one key 'aws': %v", got1)
				}

				if !exists && tt.wantErr {
					t.Errorf("GetTemplatesPath() error = %v, wantErr %v", val, tt.wantErr)
				}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetTemplatesPath() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCatalog_OpenFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			"valid key",
			"ssl/deprecated-tls.yaml",
			false,
		},
		{
			"nonexistent key",
			"something/that-doesnt-exist.yaml",
			true,
		},
		{
			"path to folder",
			"cves/2023",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewCatalog("bucket", withMockS3Service())
			got, err := c.OpenFile(tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("OpenFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && got == nil {
				t.Error("OpenFile() didn't return error but io.ReadCloser is nil")
			}
		})
	}
}

func TestCatalog_ResolvePath(t *testing.T) {
	type args struct {
		templateName string
		second       string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			"absolute path",
			args{
				"ssl/deprecated-tls.yaml",
				"",
			},
			"ssl/deprecated-tls.yaml",
			false,
		},
		{
			"relative path with second param",
			args{
				"deprecated-tls.yaml",
				"ssl/",
			},
			"ssl/deprecated-tls.yaml",
			false,
		},
		{
			"relative path and no second param",
			args{
				"cves/2023",
				"",
			},
			"",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewCatalog("bucket", withMockS3Service())
			got, err := c.ResolvePath(tt.args.templateName, tt.args.second)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolvePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ResolvePath() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func withMockS3Service() func(*Catalog) error {
	return func(c *Catalog) error {
		c.svc = newMockS3Service()
		return nil
	}
}

type mocks3svc struct {
	keys []string
}

func newMockS3Service() mocks3svc {
	return mocks3svc{
		keys: []string{
			"ssl/deprecated-tls.yaml",
			"ssl/detect-ssl-issuer.yaml",
			"ssl/expired-ssl.yaml",
			"ssl/mismatched-ssl.yaml",
			"cves/2023/CVE-2023-0669.yaml",
			"cves/2023/CVE-2023-23488.yaml",
			"cves/2023/CVE-2023-23489.yaml",
		},
	}
}

func (m mocks3svc) getAllKeys() ([]string, error) {
	return m.keys, nil
}

func (m mocks3svc) downloadKey(name string) (io.ReadCloser, error) {
	found := false
	for _, key := range m.keys {
		if key == name {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("key not found")
	}

	sample := `
id: git-config

info:
  name: Git Config File
  author: Ice3man
  severity: medium
  description: Searches for the pattern /.git/config on passed URLs.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers:
      - type: word
        words:
          - "[core]"
`

	return io.NopCloser(strings.NewReader(sample)), nil
}

func (m mocks3svc) setBucket(bucket string) {}
