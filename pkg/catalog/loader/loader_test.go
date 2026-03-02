package loader

import (
	"reflect"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplates(t *testing.T) {
	catalog := disk.NewCatalog("")

	store, err := New(&Config{
		Templates: []string{"cves/CVE-2021-21315.yaml"},
		Catalog:   catalog,
	})
	require.Nil(t, err, "could not load templates")
	require.Equal(t, []string{"cves/CVE-2021-21315.yaml"}, store.finalTemplates, "could not get correct templates")

	templatesDirectory := "/test"
	config.DefaultConfig.TemplatesDirectory = templatesDirectory
	t.Run("blank", func(t *testing.T) {
		store, err := New(&Config{
			Catalog: catalog,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{templatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
	t.Run("only-tags", func(t *testing.T) {
		store, err := New(&Config{
			Tags:    []string{"cves"},
			Catalog: catalog,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{templatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
	t.Run("tags-with-path", func(t *testing.T) {
		store, err := New(&Config{
			Tags:    []string{"cves"},
			Catalog: catalog,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{templatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
}

func TestRemoteTemplates(t *testing.T) {
	catalog := disk.NewCatalog("")

	var nilStringSlice []string
	type args struct {
		config *Config
	}
	tests := []struct {
		name    string
		args    args
		want    *Store
		wantErr bool
	}{
		{
			name: "remote-templates-positive",
			args: args{
				config: &Config{
					TemplateURLs:             []string{"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/technologies/tech-detect.yaml"},
					RemoteTemplateDomainList: []string{"localhost", "raw.githubusercontent.com"},
					Catalog:                  catalog,
				},
			},
			want: &Store{
				finalTemplates: []string{"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/technologies/tech-detect.yaml"},
			},
			wantErr: false,
		},
		{
			name: "remote-templates-negative",
			args: args{
				config: &Config{
					TemplateURLs:             []string{"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/technologies/tech-detect.yaml"},
					RemoteTemplateDomainList: []string{"localhost"},
					Catalog:                  catalog,
				},
			},
			want: &Store{
				finalTemplates: nilStringSlice,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.finalTemplates, tt.want.finalTemplates) {
				t.Errorf("New() = %v, want %v", got.finalTemplates, tt.want.finalTemplates)
			}
		})
	}
}

func TestLoadTemplates_NoDialers(t *testing.T) {
	catalog := disk.NewCatalog("")

	options := &protocols.ExecutorOptions{
		Options: &types.Options{
			ExecutionId: "non-existent-id",
			Logger:      gologger.DefaultLogger,
		},
	}

	store, err := New(&Config{
		Templates:       []string{"test"},
		Catalog:         catalog,
		ExecutorOptions: options,
		Logger:          gologger.DefaultLogger,
	})
	if err != nil {
		t.Fatalf("unexpected loader creation error: %v", err)
	}

	// This should now return an error instead of panicking.
	_, err = store.LoadTemplatesWithTags([]string{"test"}, []string{"test"})
	if err == nil {
		t.Fatal("expected error when dialers are missing, got nil")
	}
	if !strings.Contains(err.Error(), "dialers with executionId") {
		t.Errorf("unexpected error message: %v", err)
	}
}
