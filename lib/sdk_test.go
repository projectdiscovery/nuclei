package nuclei_test

import (
	"testing"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/stretchr/testify/require"
)

func TestSimpleNuclei(t *testing.T) {
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}),
		nuclei.EnableStatsWithOpts(nuclei.StatsOptions{JSON: true}),
	)
	require.Nil(t, err)
	ne.LoadTargets([]string{"scanme.sh"}, false) // probe non http/https target is set to false here
	// when callback is nil it nuclei will print JSON output to stdout
	err = ne.ExecuteWithCallback(nil)
	require.Nil(t, err)
	defer ne.Close()
}

func TestSimpleNucleiRemote(t *testing.T) {
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplatesOrWorkflows(
			nuclei.TemplateSources{
				RemoteTemplates: []string{"https://cloud.projectdiscovery.io/public/nameserver-fingerprint.yaml"},
			},
		),
	)
	require.Nil(t, err)
	ne.LoadTargets([]string{"scanme.sh"}, false) // probe non http/https target is set to false here
	err = ne.LoadAllTemplates()
	require.Nil(t, err, "could not load templates")
	// when callback is nil it nuclei will print JSON output to stdout
	err = ne.ExecuteWithCallback(nil)
	require.Nil(t, err)
	defer ne.Close()
}

func TestThreadSafeNuclei(t *testing.T) {
	// create nuclei engine with options
	ne, err := nuclei.NewThreadSafeNucleiEngine()
	require.Nil(t, err)

	// scan 1 = run dns templates on scanme.sh
	t.Run("scanme.sh", func(t *testing.T) {
		err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}))
		require.Nil(t, err)
	})

	// scan 2 = run dns templates on honey.scanme.sh
	t.Run("honey.scanme.sh", func(t *testing.T) {
		err = ne.ExecuteNucleiWithOpts([]string{"honey.scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}))
		require.Nil(t, err)
	})

	// wait for all scans to finish
	defer ne.Close()
}
