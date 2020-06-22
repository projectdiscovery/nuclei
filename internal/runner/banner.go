package runner

import "github.com/projectdiscovery/gologger"

const banner = `
                       __     _ 
     ____  __  _______/ /__  (_)
    / __ \/ / / / ___/ / _ \/ / 
   / / / / /_/ / /__/ /  __/ /  
  /_/ /_/\__,_/\___/_/\___/_/   v1									  
`

// Version is the current version of nuclei
const Version = `1.1.7`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
	gologger.Printf("\t\tprojectdiscovery.io\n\n")

	gologger.Labelf("Use with caution. You are responsible for your actions\n")
	gologger.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
