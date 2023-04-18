package installer

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	updateutils "github.com/projectdiscovery/utils/update"
)

// NucleiToolUpdateCallback updates nuclei binary/tool to latest version
func NucleiToolUpdateCallback() {
	updateutils.GetUpdateToolCallback("nuclei", config.Version)
}

func NucleiTemplatesUpdateCallback() {
	tm := &TemplateManager{}
	if err := tm.UpdateIfOutdated(); err != nil {
		gologger.Fatal().Msgf("Could not update nuclei templates: %s", err)
	}
}
