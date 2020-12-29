package runner

import "github.com/projectdiscovery/gologger"

const banner = `
                       __     _
     ____  __  _______/ /__  (_)
    / __ \/ / / / ___/ / _ \/ /
   / / / / /_/ / /__/ /  __/ /
  /_/ /_/\__,_/\___/_/\___/_/   v2.2.1-dev
`

// Version is the current version of nuclei
const Version = `2.2.1-dev`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")

	gologger.Warning().Msgf("Use with caution. You are responsible for your actions\n")
	gologger.Warning().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
