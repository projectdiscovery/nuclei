package nuclei

import (
	"os"
	"reflect"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	pkgtypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
)

// loadReportingConfigFromPath reads a -report-config style YAML at path, parses
// it via runner.LoadReportingOptionsFromBytes, and stores the result on e.
// Shared between WithReportingConfigFile and loadImplicitReportingConfig.
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

// loadImplicitReportingConfig mirrors the CLI behaviour where setting
// `report-config: <path>` inside the main -config file is enough to activate
// reporting. We skip the lookup when reportingOpts was already set by an
// explicit WithReportingConfig* option earlier in the chain.
func loadImplicitReportingConfig(e *NucleiEngine) error {
	if e.opts.ReportingConfig == "" || e.reportingOpts != nil {
		return nil
	}
	return loadReportingConfigFromPath(e, e.opts.ReportingConfig)
}

// newConfigFlagSet builds a goflags.FlagSet bound to the given *types.Options
// using the same flag inventory the CLI exposes. Used by the config-overlay
// helper to materialise both a "flag-defaults only" baseline and a
// "flag-defaults + YAML" overlay so they can be diffed reflectively.
func newConfigFlagSet(opts *pkgtypes.Options) *goflags.FlagSet {
	fs := goflags.NewFlagSet()
	fs.CaseSensitive = true
	runner.BindOptionFlags(fs, opts)
	return fs
}

// overlayConfigFromFile applies only the YAML-set fields from path into dst.
//
// goflags writes the flag-registered default into the bound pointer at
// registration time, so binding directly to dst would clobber dst's existing
// values. Instead we build two scratch *types.Options:
//   - baseline: flag-defaults only (no YAML merged).
//   - overlay:  flag-defaults + YAML overrides.
//
// Fields where baseline != overlay are the ones the YAML touched; those fields
// (and only those) are copied into dst.
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
