package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
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
	templatesDirectory := filepath.Join(home, "nuclei-templates")

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.`)

	/* TODO Important: The defined default values, especially for slice/array types are NOT DEFAULT VALUES, but rather implicit values to which the user input is appended.
	This can be very confusing and should be addressed
	*/

	createGroup(flagSet, "input", "Target",
		flagSet.StringSliceVarP(&options.Targets, "u", "target", []string{}, "input url/host to scan"),
		flagSet.StringVarP(&options.TargetsFilePath, "l", "list", "", "input file containing list of target urls/hosts to scan (one per line)"),
	)

	createGroup(flagSet, "template", "Template",
		flagSet.StringSliceVarP(&options.Templates, "t", "templates", []string{}, "template or directory including templates to run"),
		flagSet.BoolVarP(&options.NewTemplates, "nt", "new-templates", false, "new templates to run added in latest nuclei-templates release"),
		flagSet.NormalizedStringSliceVar(&options.Tags, "tags", []string{}, "templates to use for scan based on provided tags, comma separated multiple values can be used."),
		flagSet.StringSliceVarP(&options.Workflows, "w", "workflows", []string{}, "workflow or directory including workflows to run"),
		flagSet.BoolVar(&options.Validate, "validate", false, "validate provided templates/workflows syntax against nuclei engine"),
		flagSet.BoolVar(&options.TemplateList, "tl", false, "list all available templates"),
	)

	createGroup(flagSet, "filters", "template-filter",
		flagSet.NormalizedStringSliceVarP(&options.ExcludeTags, "etags", "exclude-tags", []string{}, "exclude templates from scan based on given tags, comma separated multiple values can be used."),
		flagSet.NormalizedStringSliceVarP(&options.IncludeTags, "itags", "include-tags", []string{}, "include templates in scan based on given tags (overwrites default deny list of tags to run more intrusive templates)"), // TODO show default deny list
		flagSet.StringSliceVarP(&options.ExcludedTemplates, "et", "exclude-templates", []string{}, "exclude template or directory including templates from scan"),
		flagSet.StringSliceVarP(&options.IncludeTemplates, "it", "include-templates", []string{}, "include template or directory including templates in scan (overwrites default deny list of templates to run more intrusive templates)"),
		flagSet.VarP(&options.Severities, "s", "severity", fmt.Sprintf("templates to run based on severity, comma separated multiple values can be used. Possible values: %s", severity.GetSupportedSeverities().String())),
		flagSet.VarP(&options.ExcludeSeverities, "es", "exclude-severity", fmt.Sprintf("templates to exclude based on severity, comma separated multiple values can be used. Possible values: %s", severity.GetSupportedSeverities().String())),
		flagSet.NormalizedStringSliceVarP(&options.Author, "a", "author", []string{}, "templates to run based on given author, comma separated multiple values can be used."),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.Output, "o", "output", "", "output file to write found issues/vulnerabilities"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display findings only"),
		flagSet.BoolVarP(&options.NoColor, "nc", "no-color", false, "disable output content coloring (ANSI escape codes)"),
		flagSet.BoolVar(&options.JSON, "json", false, "write output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.JSONRequests, "irr", "include-rr", false, "include request/response pairs in the JSONL output"),
		flagSet.BoolVarP(&options.NoMeta, "nm", "no-meta", false, "disable printing results metadata in CLI output"),
		flagSet.BoolVarP(&options.NoTimestamp, "nts", "no-timestamp", false, "disable printing timestamp information in CLI output"),
		flagSet.StringVarP(&options.MarkdownExportDirectory, "me", "markdown-export", "", "directory to export results in markdown format"),
		flagSet.StringVarP(&options.SarifExport, "se", "sarif-export", "", "file to export results in SARIF format"),
	)

	createGroup(flagSet, "configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the nuclei configuration file"),
		flagSet.StringVarP(&options.ReportingConfig, "rc", "report-config", "", "reporting module configuration file"), // TODO merge into the config file or rename to issue-tracking
		flagSet.StringVarP(&options.ReportingDB, "rdb", "report-db", "", "reporting database path (used for storing results locally to only report unique finding between multiple scan)"),
		flagSet.StringSliceVarP(&options.CustomHeaders, "H", "header", []string{}, "custom headers to include in HTTP request"),
		flagSet.RuntimeMapVarP(&options.Vars, "V", "var", []string{}, "cli variable to pass values in templates dynamically"),
		flagSet.StringVarP(&options.ResolversFile, "r", "resolvers", "", "file containing resolver list to use"),
		flagSet.BoolVarP(&options.SystemResolvers, "sr", "system-resolvers", false, "use system DNS resolving as error fallback"),
		flagSet.BoolVar(&options.OfflineHTTP, "passive", false, "enable passive HTTP response processing mode"),
		flagSet.BoolVarP(&options.EnvironmentVariables, "ev", "env-vars", false, "enable environment variables to be used in template"),
	)

	createGroup(flagSet, "interactsh", "interactsh",
		flagSet.StringVarP(&options.InteractshURL, "iserver", "interactsh-server", "https://interactsh.com", "self-hosted interactsh server to use"),
		flagSet.StringVarP(&options.InteractshToken, "itoken", "interactsh-token", "", "authentication token for self-hosted interactsh server"),
		flagSet.IntVarP(&options.InteractionsCacheSize, "ics", "interactions-cache-size", 5000, "number of requests to keep in the interactions cache"),
		flagSet.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "number of seconds to wait before evicting requests from cache"),
		flagSet.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "number of seconds to wait before each interaction poll request"),
		flagSet.IntVar(&options.InteractionsColldownPeriod, "interactions-cooldown-period", 5, "extra time for interaction polling before exiting"),
		flagSet.BoolVarP(&options.NoInteractsh, "ni", "no-interactsh", false, "disable the use of interactsh server (oob based templates will be also excluded)"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.RateLimit, "rl", "rate-limit", 150, "maximum number of requests to send per second"),
		flagSet.IntVarP(&options.RateLimitMinute, "rlm", "rate-limit-minute", 0, "maximum number of requests to send per minute"),
		flagSet.IntVarP(&options.BulkSize, "bs", "bulk-size", 25, "maximum number of hosts to be analyzed in parallel per template"),
		flagSet.IntVarP(&options.TemplateThreads, "c", "concurrency", 25, "maximum number of templates to be executed in parallel"),
	)

	createGroup(flagSet, "optimization", "Optimizations",
		flagSet.IntVar(&options.Timeout, "timeout", 5, "time to wait in seconds before timeout"),
		flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request"),
		flagSet.IntVarP(&options.MaxHostError, "mhe", "max-host-error", 10, "max errors for a host before skipping from scan"),
		flagSet.BoolVar(&options.Project, "project", false, "enable project option to store compressed version of scanned data on disk"),
		flagSet.StringVar(&options.ProjectPath, "project-path", os.TempDir(), "custom path to store compressed scanned data on disk"),
		flagSet.BoolVarP(&options.StopAtFirstMatch, "spm", "stop-at-first-path", false, "stop processing HTTP requests after the first match (may break template/workflow logic)"),
		flagSet.BoolVar(&options.Stream, "stream", false, "stream mode - start elaborating without sorting the input"),
	)

	createGroup(flagSet, "headless", "Headless",
		flagSet.BoolVar(&options.Headless, "headless", false, "enable headless engine to run headless based templates"),
		flagSet.IntVar(&options.PageTimeout, "page-timeout", 20, "seconds to wait for each page in headless mode"),
		flagSet.BoolVar(&options.ShowBrowser, "show-browser", false, "show the browser on the screen when running templates with headless mode"),
		flagSet.BoolVar(&options.UseInstalledChrome, "system-chrome", false, "use local installed chrome browser instead of nuclei installed"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
		flagSet.BoolVar(&options.DebugRequests, "debug-req", false, "show all sent requests"),
		flagSet.BoolVar(&options.DebugResponse, "debug-resp", false, "show all received responses"),

		/* TODO why the separation? http://proxy:port vs socks5://proxy:port etc
		   TODO should auto-set the HTTP_PROXY variable for the process? */
		flagSet.StringVarP(&options.ProxyURL, "proxy", "proxy-url", "", "http proxy to use with scan"),
		flagSet.StringVar(&options.ProxySocksURL, "proxy-socks-url", "", "socks proxy to use with scan"),
		flagSet.StringVar(&options.TraceLogFile, "trace-log", "", "file to write sent requests trace log"),
		flagSet.BoolVar(&options.Version, "version", false, "display nuclei version"),
		flagSet.BoolVarP(&options.Verbose, "v", "verbose", false, "display verbose output"),
		flagSet.BoolVar(&options.VerboseVerbose, "vv", false, "display extra verbose information"),
		flagSet.BoolVarP(&options.TemplatesVersion, "tv", "templates-version", false, "shows the version of the installed nuclei-templates"),
	)

	createGroup(flagSet, "update", "Update",
		flagSet.BoolVar(&options.UpdateNuclei, "update", false, "update nuclei engine to the latest released version"),
		flagSet.BoolVarP(&options.UpdateTemplates, "ut", "update-templates", false, "update nuclei-templates to the latest released version"),
		flagSet.StringVarP(&options.TemplatesDirectory, "ud", "update-directory", templatesDirectory, "overwrite the default nuclei-templates directory to install"),
		flagSet.BoolVarP(&options.NoUpdateTemplates, "nut", "no-update-templates", false, "do not check for nuclei/templates updates"),
	)

	createGroup(flagSet, "stats", "Statistics",
		flagSet.BoolVar(&options.EnableProgressBar, "stats", false, "display statistics about the running scan"),
		flagSet.BoolVar(&options.StatsJSON, "stats-json", false, "write statistics data to an output file in JSONL(ines) format"),
		flagSet.IntVarP(&options.StatsInterval, "si", "stats-interval", 5, "number of seconds to wait between showing a statistics update"),
		flagSet.BoolVar(&options.Metrics, "metrics", false, "expose nuclei metrics on a port"),
		flagSet.IntVar(&options.MetricsPort, "metrics-port", 9092, "port to expose nuclei metrics on"),
	)

	_ = flagSet.Parse()

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
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

/*
HacktoberFest update: Below, you can find our ticket recommendations. Tasks with the "good first issue" label are suitable for first time contributors. If you have other ideas, or need help with getting started, join our Discord channel or reach out to @forgedhallpass.

https://github.com/issues?q=is%3Aopen+is%3Aissue+user%3Aprojectdiscovery+label%3AHacktoberfest

*/
