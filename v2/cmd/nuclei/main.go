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
	set.SetDescription(`Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use.`)

	createGroup(set, "input", "Input Options",
		set.StringVarP(&options.Target, "target", "u", "", "target URL/host to scan"),
		set.StringVarP(&options.Targets, "list", "l", "", "path to file containing a list of target URLs/hosts to scan (one per line)"),
	)

	createGroup(set, "templates", "Templates Options",
		set.StringSliceVarP(&options.Templates, "templates", "t", []string{}, "templates or directory names to run"),
		set.StringSliceVarP(&options.Workflows, "workflows", "w", []string{}, "list of workflows to run"),
		set.BoolVarP(&options.NewTemplates, "new-templates", "nt", false, "run newly added templates only"),
	)

	createGroup(set, "filters", "Template Filter Options",
		set.StringSliceVar(&options.Tags, "tags", []string{}, "execute a subset of templates that contain the provided tags"),
		set.StringSliceVar(&options.IncludeTags, "include-tags", []string{}, "list of tags from the default deny list that permit executing more intrusive templates"), // TODO show default deny list
		set.StringSliceVarP(&options.ExcludeTags, "exclude-tags", "etags", []string{}, "exclude templates with the provided tags"),

		set.StringSliceVar(&options.IncludeTemplates, "include-templates", []string{}, "list of templates to be executed even if they are excluded either by default or configuration"),
		set.StringSliceVarP(&options.ExcludedTemplates, "exclude", "exclude-templates", []string{}, "templates or directory names to exclude"),

		set.StringSliceVarP(&options.Severity, "impact", "severity", []string{}, "execute templates that match the provided severities only"),
		set.StringSliceVar(&options.Author, "author", []string{}, "execute templates that are (co-)created by the specified authors"),
	)

	createGroup(set, "output", "Output Options",
		set.StringVarP(&options.Output, "output", "o", "", "output file to write found issues/vulnerabilities"),

		set.BoolVar(&options.JSON, "json", false, "write output in JSONL(ines) format"),
		set.BoolVarP(&options.JSONRequests, "include-rr", "irr", false, "include request/response pairs in the JSON output (for findings only)"),

		set.StringVarP(&options.DiskExportDirectory, "markdown-export", "me", "", "directory to export results in markdown format"),
		set.StringVarP(&options.ReportingConfig, "report-config", "rc", "", "nuclei reporting module configuration file"), // TODO merge into the config file or rename to issue-tracking
		set.StringVarP(&options.ReportingDB, "report-db", "rdb", "", "local nuclei reporting database (always use this to persist report data)"),
		set.StringVarP(&options.SarifExport, "sarif-export", "se", "", "file to export results in SARIF format"),
	)

	createGroup(set, "rate-limit", "Rate-Limit Options",
		set.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum number of requests to send per second"),
		set.IntVarP(&options.BulkSize, "bulk-size", "bs", 25, "maximum number of hosts to be analyzed in parallel per template"),
		set.IntVarP(&options.TemplateThreads, "concurrency", "c", 10, "maximum number of templates to be executed in parallel"),
	)

	createGroup(set, "options", "Engine Options",
		set.StringVar(&cfgFile, "config", "", "path to the nuclei configuration file"),
		set.StringSliceVarP(&options.CustomHeaders, "header", "H", []string{}, "custom headers in header:value format"),
		set.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
		set.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request"),
		set.IntVar(&options.Timeout, "timeout", 5, "time to wait in seconds before timeout"),
		set.BoolVarP(&options.NoMeta, "no-meta", "nm", false, "don't display match metadata"),
		set.BoolVarP(&options.StopAtFirstMatch, "stop-at-first-path", "spm", false, "stop processing HTTP requests after the first match (may break template/workflow logic)"),
		set.BoolVar(&options.OfflineHTTP, "passive", false, "enable passive HTTP response processing mode"),
		set.StringVarP(&options.ResolversFile, "resolvers", "r", "", "file containing resolver list for nuclei"),
		set.BoolVar(&options.SystemResolvers, "system-resolvers", false, "use system DNS resolving as error fallback"),
	)

	createGroup(set, "interactsh", "interactsh Options",
		set.StringVar(&options.InteractshURL, "interactsh-url", "https://interact.sh", "self-hosted Interactsh Server URL"),
		set.IntVar(&options.InteractionsCacheSize, "interactions-cache-size", 5000, "number of requests to keep in the interactions cache"),
		set.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "number of seconds to wait before evicting requests from cache"),
		set.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "number of seconds to wait before each interaction poll request"),
		set.IntVar(&options.InteractionsColldownPeriod, "interactions-cooldown-period", 5, "extra time for interaction polling before exiting"),
		set.BoolVar(&options.NoInteractsh, "no-interactsh", false, "do not use interactsh server for blind interaction polling"),
	)

	createGroup(set, "headless", "Headless Options",
		set.BoolVar(&options.Headless, "headless", false, "enable templates that require headless browser support"),
		set.IntVar(&options.PageTimeout, "page-timeout", 20, "seconds to wait for each page in headless mode"),
		set.BoolVar(&options.ShowBrowser, "show-browser", false, "show the browser on the screen when running templates with headless mode"),
	)

	createGroup(set, "proxy", "Proxy Options", // TODO should auto-set the HTTP_PROXY variable for the process?
		set.StringVarP(&options.ProxyURL, "proxy-url", "proxy", "", "URL of the HTTP proxy server"), // TODO why the separation? http://proxy:port vs socks5://proxy:port etc
		set.StringVar(&options.ProxySocksURL, "proxy-socks-url", "", "URL of the SOCKS proxy server"),
	)

	createGroup(set, "stats", "Stats Options",
		set.BoolVar(&options.EnableProgressBar, "stats", false, "display statistics about the running scan"),
		set.BoolVar(&options.StatsJSON, "stats-json", false, "write statistics data to and output file in JSONL(ines) format"),
		set.IntVarP(&options.StatsInterval, "stats-interval", "si", 5, "number of seconds to wait between showing a statistics update"),
		set.BoolVar(&options.Metrics, "metrics", false, "expose nuclei metrics on a port"),
		set.IntVar(&options.MetricsPort, "metrics-port", 9092, "port to expose nuclei metrics on"),
	)

	createGroup(set, "debug", "Debug Options",
		set.BoolVarP(&options.Verbose, "verbose", "v", false, "show verbose output"),
		set.BoolVar(&options.VerboseVerbose, "vv", false, "display extra verbose information"),
		set.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
		set.BoolVar(&options.DebugRequests, "debug-req", false, "show all sent requests"),
		set.BoolVar(&options.DebugResponse, "debug-resp", false, "show all received responses"),
		set.BoolVar(&options.Silent, "silent", false, "display findings only"),
		set.BoolVar(&options.Version, "version", false, "show nuclei version"),
		set.BoolVarP(&options.TemplatesVersion, "templates-version", "tv", false, "shows the version of the installed nuclei-templates"),
		set.StringVar(&options.TraceLogFile, "trace-log", "", "file to write sent requests trace log"),
	)

	createGroup(set, "update", "Update Options",
		set.BoolVar(&options.UpdateNuclei, "update", false, "update nuclei to the latest released version"),
		set.BoolVarP(&options.UpdateTemplates, "update-templates", "ut", false, "update the community templates to latest released version"),
		set.StringVarP(&options.TemplatesDirectory, "update-directory", "ud", templatesDirectory, "overwrite the default nuclei-templates directory"),
	)

	set.BoolVar(&options.Project, "project", false, "use a project folder to avoid sending same request multiple times")
	set.StringVar(&options.ProjectPath, "project-path", os.TempDir(), "set a specific project path")
	set.BoolVar(&options.TemplateList, "tl", false, "list all available templates")
	set.BoolVar(&options.Validate, "validate", false, "validate the passed templates to nuclei")

	_ = set.Parse()

	if cfgFile != "" {
		if err := set.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
