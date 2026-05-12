package nuclei

import (
	"os"
	"reflect"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	pkgtypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
)

// loadReportingConfigFromPath reads + parses a -report-config YAML at path
// and stores the result on e.
func loadReportingConfigFromPath(e *NucleiEngine, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errkit.Wrap(err, "could not open reporting config file")
	}
	ropts, err := runner.LoadReportingOptionsFromBytes(data)
	if err != nil {
		return errkit.Wrap(err, "could not parse reporting config file")
	}
	e.reportingOpts = ropts
	return nil
}

// loadImplicitReportingConfig loads the reporting YAML pointed at by
// opts.ReportingConfig, matching the CLI's `report-config:` behaviour. Skipped
// when an explicit WithReportingConfig* already set reportingOpts.
func loadImplicitReportingConfig(e *NucleiEngine) error {
	if e.opts.ReportingConfig == "" || e.reportingOpts != nil {
		return nil
	}
	return loadReportingConfigFromPath(e, e.opts.ReportingConfig)
}

// newConfigFlagSet binds the shared flag inventory to opts. Used to build the
// baseline and overlay structs for the reflection-based YAML diff.
func newConfigFlagSet(opts *pkgtypes.Options) *goflags.FlagSet {
	fs := goflags.NewFlagSet()
	fs.CaseSensitive = true
	runner.BindOptionFlags(fs, opts)
	return fs
}

// overlayConfigFromFile applies only YAML-set fields from path into dst.
//
// goflags writes flag defaults into the bound pointer at registration, so
// binding directly to dst would clobber existing values. We diff a baseline
// (flag-defaults only) against an overlay (flag-defaults + YAML); fields that
// differ are the ones the YAML touched and get copied into dst.
func overlayConfigFromFile(dst *pkgtypes.Options, path string) error {
	baseline := &pkgtypes.Options{}
	_ = newConfigFlagSet(baseline)

	overlay := &pkgtypes.Options{}
	fs := newConfigFlagSet(overlay)
	if err := fs.MergeConfigFile(path); err != nil {
		return err
	}

	applyOverlay(dst, baseline, overlay)
	return nil
}

// applyOverlay copies any field from overlay into dst where overlay differs
// from baseline. Unexported / non-settable fields are skipped.
func applyOverlay(dst, baseline, overlay *pkgtypes.Options) {
	dstV := reflect.ValueOf(dst).Elem()
	baseV := reflect.ValueOf(baseline).Elem()
	overV := reflect.ValueOf(overlay).Elem()

	for i := 0; i < dstV.NumField(); i++ {
		df := dstV.Field(i)
		if !df.CanSet() {
			continue
		}
		bf := baseV.Field(i)
		of := overV.Field(i)
		if reflect.DeepEqual(bf.Interface(), of.Interface()) {
			continue
		}
		df.Set(of)
	}
}
