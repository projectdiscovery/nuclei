package loader

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
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
