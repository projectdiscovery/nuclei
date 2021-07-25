package main

import (
	"os"
	"path"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

var (
	cfgFile string
	options = &types.Options{}
)

func main() {
	readConfig()

	runner.ParseOptions(options)

	nucleiRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	if nucleiRunner == nil {
		return
	}
	if err := nucleiRunner.RunEnumeration(); err != nil {
		gologger.Fatal().Msgf("Could not run nuclei: %s\n", err)
	}
	nucleiRunner.Close()
}

func readConfig() {
	home, _ := os.UserHomeDir()
	templatesDirectory := path.Join(home, "nuclei-templates")

	set := goflags.NewFlagSet()
	set.SetDescription(`Nuclei is a fast tool for configurable targeted scanning 
based on templates offering massive extensibility and ease of use.`)

	set.SetGroup("input", "Input Options")
	set.StringVarP(&options.Target, "target", "u", "", "URL/Host to scan with nuclei").Group("input")
	set.StringVarP(&options.Targets, "list", "l", "", "List of URLs/Hosts to run templates on").Group("input")

	set.SetGroup("templates", "Templates Options")
	set.StringSliceVarP(&options.Templates, "templates", "t", []string{}, "Templates to run, supports single and multiple templates using directory.").Group("templates")
	set.StringSliceVarP(&options.Workflows, "workflows", "w", []string{}, "Workflows to run for nuclei").Group("templates")
	set.BoolVarP(&options.NewTemplates, "new-templates", "nt", false, "Only run newly added templates").Group("templates")

	set.SetGroup("filters", "Template Filters")
	set.StringSliceVar(&options.Tags, "tags", []string{}, "Tags to execute templates for").Group("filters")
	set.StringSliceVarP(&options.Severity, "impact", "severity", []string{}, "Templates to run based on severity").Group("filters")
	set.StringSliceVar(&options.Author, "author", []string{}, "Templates to run based on author").Group("filters")
	set.StringSliceVarP(&options.ExcludedTemplates, "exclude", "exclude-templates", []string{}, "Templates to exclude, supports single and multiple templates using directory.").Group("filters")
	set.StringSliceVarP(&options.ExcludeTags, "exclude-tags", "etags", []string{}, "Exclude templates with the provided tags").Group("filters")
	set.StringSliceVar(&options.IncludeTemplates, "include-templates", []string{}, "Templates to force run even if they are in denylist").Group("filters")
	set.StringSliceVar(&options.IncludeTags, "include-tags", []string{}, "Tags to force run even if they are in denylist").Group("filters")

	set.SetGroup("output", "Output Options")
	set.StringVarP(&options.Output, "output", "o", "", "File to write output to (optional)").Group("output")
	set.BoolVar(&options.JSON, "json", false, "Write json output to files").Group("output")
	set.BoolVarP(&options.JSONRequests, "include-rr", "irr", false, "Write requests/responses for matches in JSON output").Group("output")
	set.StringVarP(&options.DiskExportDirectory, "markdown-export", "me", "", "Directory to export results in markdown format").Group("output")
	set.StringVarP(&options.ReportingConfig, "report-config", "rc", "", "Nuclei Reporting Module configuration file").Group("output")
	set.StringVarP(&options.ReportingDB, "report-db", "rdb", "", "Local Nuclei Reporting Database (Always use this to persistent report data)").Group("output")
	set.StringVarP(&options.SarifExport, "sarif-export", "se", "", "File to export results in sarif format").Group("output")

	set.SetGroup("rate-limit", "Rate-Limit Options")
	set.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "Maximum requests to send per second").Group("rate-limit")
	set.IntVarP(&options.BulkSize, "bulk-size", "bs", 25, "Maximum Number of hosts analyzed in parallel per template").Group("rate-limit")
	set.IntVarP(&options.TemplateThreads, "concurrency", "c", 10, "Maximum Number of templates executed in parallel").Group("rate-limit")

	set.SetGroup("options", "Engine Options")
	set.StringVar(&cfgFile, "config", "", "Nuclei configuration file").Group("options")
	set.StringSliceVarP(&options.CustomHeaders, "header", "H", []string{}, "Custom Header.").Group("options")
	set.BoolVarP(&options.NoColor, "no-color", "nc", false, "Disable colors in output").Group("options")
	set.IntVar(&options.Retries, "retries", 1, "Number of times to retry a failed request").Group("options")
	set.IntVar(&options.Timeout, "timeout", 5, "Time to wait in seconds before timeout").Group("options")
	set.BoolVarP(&options.NoMeta, "no-meta", "nm", false, "Don't display metadata for the matches").Group("options")
	set.BoolVarP(&options.StopAtFirstMatch, "stop-at-first-path", "spm", false, "Stop processing http requests at first match (this may break template/workflow logic)").Group("options")
	set.BoolVar(&options.OfflineHTTP, "passive", false, "Enable Passive HTTP response processing mode").Group("options")
	set.StringVarP(&options.ResolversFile, "resolvers", "r", "", "File containing resolver list for nuclei").Group("options")
	set.BoolVar(&options.SystemResolvers, "system-resolvers", false, "Use system dns resolving as error fallback").Group("options")

	set.SetGroup("interactsh", "interactsh Options")
	set.StringVar(&options.InteractshURL, "interactsh-url", "https://interact.sh", "Self Hosted Interactsh Server URL").Group("interactsh")
	set.IntVar(&options.InteractionsCacheSize, "interactions-cache-size", 5000, "Number of requests to keep in interactions cache").Group("interactsh")
	set.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "Number of seconds to wait before evicting requests from cache").Group("interactsh")
	set.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "Number of seconds before each interaction poll request").Group("interactsh")
	set.IntVar(&options.InteractionsColldownPeriod, "interactions-cooldown-period", 5, "Extra time for interaction polling before exiting").Group("interactsh")
	set.BoolVar(&options.NoInteractsh, "no-interactsh", false, "Do not use interactsh server for blind interaction polling").Group("interactsh")

	set.SetGroup("headless", "Headless Options")
	set.BoolVar(&options.Headless, "headless", false, "Enable headless browser based templates support").Group("headless")
	set.IntVar(&options.PageTimeout, "page-timeout", 20, "Seconds to wait for each page in headless mode").Group("headless")
	set.BoolVar(&options.ShowBrowser, "show-browser", false, "Show the browser on the screen in headless mode").Group("headless")

	set.SetGroup("proxy", "Proxy Options")
	set.StringVarP(&options.ProxyURL, "proxy-url", "proxy", "", "URL of the proxy server").Group("proxy")
	set.StringVar(&options.ProxySocksURL, "proxy-socks-url", "", "URL of the proxy socks server").Group("proxy")

	set.SetGroup("stats", "Stats Options")
	set.BoolVar(&options.EnableProgressBar, "stats", false, "Display stats of the running scan").Group("stats")
	set.BoolVar(&options.StatsJSON, "stats-json", false, "Write stats output in JSON format").Group("stats")
	set.IntVarP(&options.StatsInterval, "stats-interval", "si", 5, "Number of seconds between each stats line").Group("stats")
	set.BoolVar(&options.Metrics, "metrics", false, "Expose nuclei metrics on a port").Group("stats")
	set.IntVar(&options.MetricsPort, "metrics-port", 9092, "Port to expose nuclei metrics on").Group("stats")

	set.SetGroup("debug", "Debug Options")
	set.BoolVarP(&options.Verbose, "verbose", "v", false, "Show verbose output").Group("debug")
	set.BoolVar(&options.VerboseVerbose, "vv", false, "Display Extra Verbose Information").Group("debug")
	set.BoolVar(&options.Debug, "debug", false, "Debugging request and responses").Group("debug")
	set.BoolVar(&options.DebugRequests, "debug-req", false, "Debugging request").Group("debug")
	set.BoolVar(&options.DebugResponse, "debug-resp", false, "Debugging response").Group("debug")
	set.BoolVar(&options.Silent, "silent", false, "Show only results in output").Group("debug")
	set.BoolVar(&options.Version, "version", false, "Show version of nuclei").Group("debug")
	set.BoolVarP(&options.TemplatesVersion, "templates-version", "tv", false, "Shows the installed nuclei-templates version").Group("debug")
	set.StringVar(&options.TraceLogFile, "trace-log", "", "File to write sent requests trace log").Group("debug")

	set.SetGroup("update", "Update Options")
	set.BoolVar(&options.UpdateNuclei, "update", false, "Self Update the nuclei engine to latest").Group("update")
	set.BoolVarP(&options.UpdateTemplates, "update-templates", "ut", false, "Download / updates nuclei community templates").Group("update")
	set.StringVarP(&options.TemplatesDirectory, "update-directory", "ud", templatesDirectory, "Directory storing nuclei-templates").Group("update")

	set.BoolVar(&options.Project, "project", false, "Use a project folder to avoid sending same request multiple times")
	set.StringVar(&options.ProjectPath, "project-path", "", "Use a user defined project folder, temporary folder is used if not specified but enabled")
	set.BoolVar(&options.TemplateList, "tl", false, "List available templates")
	set.BoolVar(&options.Validate, "validate", false, "Validate the passed templates to nuclei")

	_ = set.Parse()

	if cfgFile != "" {
		if err := set.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}
}
