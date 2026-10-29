package types

import (
	"testing"

	"github.com/projectdiscovery/gologger/levels"
)

func TestResolveTemplateThreads(t *testing.T) {
	cases := []struct {
		name     string
		set      int
		disabled bool
		want     int
	}{
		{"not set, adaptive on", 0, false, AdaptiveTemplateThreads},
		{"not set, adaptive off keeps the historical default", 0, true, DefaultTemplateThreads},
		{"explicit value wins with adaptive on", 25, false, 25},
		{"explicit value wins with adaptive off", 50, true, 50},
		{"explicit high value is kept", 300, false, 300},
	}
	for _, c := range cases {
		o := &Options{TemplateThreads: c.set, DisableAdaptiveConcurrency: c.disabled}
		o.ResolveTemplateThreads()
		if o.TemplateThreads != c.want {
			t.Errorf("%s: got %d want %d", c.name, o.TemplateThreads, c.want)
		}
	}
}

func TestResolveTemplateThreadsRecordsAuto(t *testing.T) {
	auto := &Options{}
	auto.ResolveTemplateThreads()
	if !auto.TemplateThreadsAuto {
		t.Fatal("an unset -c must be recorded as automatic")
	}
	explicit := &Options{TemplateThreads: 25}
	explicit.ResolveTemplateThreads()
	if explicit.TemplateThreadsAuto {
		t.Fatal("an explicit -c must not be recorded as automatic")
	}
	if !auto.Copy().TemplateThreadsAuto {
		t.Fatal("Copy must keep TemplateThreadsAuto")
	}
}

// Raising the default logger's level must log, not panic on a nil formatter.
func TestDefaultLoggerCanBeRaised(t *testing.T) {
	o := DefaultOptions()
	o.Logger.SetMaxLevel(levels.LevelVerbose)
	o.Logger.Verbose().Msgf("verbose %d", 1)
	o.Logger.Info().Msg("info")
}
