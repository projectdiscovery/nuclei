package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/nuclei/v2/internal/runner"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	templateTypes "github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/monitor"
)

var (
	cfgFile string
)

func main() {
	if err := runner.ConfigureOptions(); err != nil {
		gologger.Fatal().Msgf("Could not initialize options: %s\n", err)
	}

	readConfig()

	runner.ParseOptions(generators.Options)

	if generators.Options.HangMonitor {
		cancel := monitor.NewStackMonitor(10 * time.Second)
		defer cancel()
	}

	nucleiRunner, err := runner.New(generators.Options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	if nucleiRunner == nil {
		return
	}

	// Setup graceful exits
	resumeFileName := types.DefaultResumeFilePath()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			nucleiRunner.Close()
			if generators.Options.ShouldSaveResume() {
				gologger.Info().Msgf("Creating resume file: %s\n", resumeFileName)
				err := nucleiRunner.SaveResumeConfig(resumeFileName)
				if err != nil {
					gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
				}
			}
			os.Exit(1)
		}
	}()

	if err := nucleiRunner.RunEnumeration(); err != nil {
		if generators.Options.Validate {
			gologger.Fatal().Msgf("Could not validate templates: %s\n", err)
		} else {
			gologger.Fatal().Msgf("Could not run nuclei: %s\n", err)
		}
	}
	nucleiRunner.Close()
	// on successful execution remove the resume file in case it exists
	if fileutil.FileExists(resumeFileName) {
		os.Remove(resumeFileName)
	}
}

func readConfig() {

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.`)

	/* TODO Important: The defined default values, especially for slice/array types are NOT DEFAULT VALUES, but rather implicit values to which the user input is appended.
	This can be very confusing and should be addressed
	*/

	flagSet.CreateGroup("input", "Target",
		flagSet.StringSliceVarP(&generators.Options.Targets, "target", "u", []string{}, "target URLs/hosts to scan"),
		flagSet.StringVarP(&generators.Options.TargetsFilePath, "list", "l", "", "path to file containing a list of target URLs/hosts to scan (one per line)"),
		flagSet.StringVar(&generators.Options.Resume, "resume", "", "Resume scan using resume.cfg (clustering will be disabled)"),
	)

	flagSet.CreateGroup("templates", "Templates",
		flagSet.BoolVarP(&generators.Options.NewTemplates, "new-templates", "nt", false, "run only new templates added in latest nuclei-templates release"),
		flagSet.CommaSeparatedStringSliceVarP(&generators.Options.NewTemplatesWithVersion, "new-templates-version", "ntv", []string{}, "run new templates added in specific version"),
		flagSet.BoolVarP(&generators.Options.AutomaticScan, "automatic-scan", "as", false, "automatic web scan using wappalyzer technology detection to tags mapping"),
		flagSet.FileNormalizedOriginalStringSliceVarP(&generators.Options.Templates, "templates", "t", []string{}, "list of template or template directory to run (comma-separated, file)"),
		flagSet.FileNormalizedOriginalStringSliceVarP(&generators.Options.TemplateURLs, "template-url", "tu", []string{}, "list of template urls to run (comma-separated, file)"),
		flagSet.FileNormalizedOriginalStringSliceVarP(&generators.Options.Workflows, "workflows", "w", []string{}, "list of workflow or workflow directory to run (comma-separated, file)"),
		flagSet.FileNormalizedOriginalStringSliceVarP(&generators.Options.WorkflowURLs, "workflow-url", "wu", []string{}, "list of workflow urls to run (comma-separated, file)"),
		flagSet.BoolVar(&generators.Options.Validate, "validate", false, "validate the passed templates to nuclei"),
		flagSet.BoolVarP(&generators.Options.NoStrictSyntax, "no-strict-syntax", "nss", false, "Disable strict syntax check on templates"),
		flagSet.BoolVar(&generators.Options.TemplateList, "tl", false, "list all available templates"),
		flagSet.StringSliceVarConfigOnly(&generators.Options.RemoteTemplateDomainList, "remote-template-domain", []string{"api.nuclei.sh"}, "allowed domain list to load remote templates from"),
	)

	flagSet.CreateGroup("filters", "Filtering",
		flagSet.FileNormalizedStringSliceVarP(&generators.Options.Authors, "author", "a", []string{}, "templates to run based on authors (comma-separated, file)"),
		flagSet.FileNormalizedStringSliceVar(&generators.Options.Tags, "tags", []string{}, "templates to run based on tags (comma-separated, file)"),
		flagSet.FileNormalizedStringSliceVarP(&generators.Options.ExcludeTags, "exclude-tags", "etags", []string{}, "templates to exclude based on tags (comma-separated, file)"),
		flagSet.FileNormalizedStringSliceVarP(&generators.Options.IncludeTags, "include-tags", "itags", []string{}, "tags to be executed even if they are excluded either by default or configuration"), // TODO show default deny list
		flagSet.FileNormalizedStringSliceVarP(&generators.Options.IncludeIds, "template-id", "id", []string{}, "templates to run based on template ids (comma-separated, file)"),
		flagSet.FileNormalizedStringSliceVarP(&generators.Options.ExcludeIds, "exclude-id", "eid", []string{}, "templates to exclude based on template ids (comma-separated, file)"),
		flagSet.FileNormalizedOriginalStringSliceVarP(&generators.Options.IncludeTemplates, "include-templates", "it", []string{}, "templates to be executed even if they are excluded either by default or configuration"),
		flagSet.FileNormalizedOriginalStringSliceVarP(&generators.Options.ExcludedTemplates, "exclude-templates", "et", []string{}, "template or template directory to exclude (comma-separated, file)"),
		flagSet.FileCommaSeparatedStringSliceVarP(&generators.Options.ExcludeMatchers, "exclude-matchers", "em", []string{}, "template matchers to exclude in result"),
		flagSet.VarP(&generators.Options.Severities, "severity", "s", fmt.Sprintf("templates to run based on severity. Possible values: %s", severity.GetSupportedSeverities().String())),
		flagSet.VarP(&generators.Options.ExcludeSeverities, "exclude-severity", "es", fmt.Sprintf("templates to exclude based on severity. Possible values: %s", severity.GetSupportedSeverities().String())),
		flagSet.VarP(&generators.Options.Protocols, "type", "pt", fmt.Sprintf("templates to run based on protocol type. Possible values: %s", templateTypes.GetSupportedProtocolTypes())),
		flagSet.VarP(&generators.Options.ExcludeProtocols, "exclude-type", "ept", fmt.Sprintf("templates to exclude based on protocol type. Possible values: %s", templateTypes.GetSupportedProtocolTypes())),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&generators.Options.Output, "output", "o", "", "output file to write found issues/vulnerabilities"),
		flagSet.BoolVarP(&generators.Options.StoreResponse, "store-resp", "sresp", false, "store all request/response passed through nuclei to output directory"),
		flagSet.StringVarP(&generators.Options.StoreResponseDir, "store-resp-dir", "srd", runner.DefaultDumpTrafficOutputFolder, "store all request/response passed through nuclei to custom directory"),
		flagSet.BoolVar(&generators.Options.Silent, "silent", false, "display findings only"),
		flagSet.BoolVarP(&generators.Options.NoColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
		flagSet.BoolVar(&generators.Options.JSON, "json", false, "write output in JSONL(ines) format"),
		flagSet.BoolVarP(&generators.Options.JSONRequests, "include-rr", "irr", false, "include request/response pairs in the JSONL output (for findings only)"),
		flagSet.BoolVarP(&generators.Options.NoMeta, "no-meta", "nm", false, "disable printing result metadata in cli output"),
		flagSet.BoolVarP(&generators.Options.NoTimestamp, "no-timestamp", "nts", false, "disable printing timestamp in cli output"),
		flagSet.StringVarP(&generators.Options.ReportingDB, "report-db", "rdb", "", "nuclei reporting database (always use this to persist report data)"),
		flagSet.BoolVarP(&generators.Options.MatcherStatus, "matcher-status", "ms", false, "display match failure status"),
		flagSet.StringVarP(&generators.Options.MarkdownExportDirectory, "markdown-export", "me", "", "directory to export results in markdown format"),
		flagSet.StringVarP(&generators.Options.SarifExport, "sarif-export", "se", "", "file to export results in SARIF format"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the nuclei configuration file"),
		flagSet.BoolVarP(&generators.Options.FollowRedirects, "follow-redirects", "fr", false, "enable following redirects for http templates"),
		flagSet.IntVarP(&generators.Options.MaxRedirects, "max-redirects", "mr", 10, "max number of redirects to follow for http templates"),
		flagSet.BoolVarP(&generators.Options.DisableRedirects, "disable-redirects", "dr", false, "disable redirects for http templates"),
		flagSet.StringVarP(&generators.Options.ReportingConfig, "report-config", "rc", "", "nuclei reporting module configuration file"), // TODO merge into the config file or rename to issue-tracking
		flagSet.FileStringSliceVarP(&generators.Options.CustomHeaders, "header", "H", []string{}, "custom header/cookie to include in all http request in header:value format (cli, file)"),
		flagSet.RuntimeMapVarP(&generators.Options.Vars, "var", "V", []string{}, "custom vars in key=value format"),
		flagSet.StringVarP(&generators.Options.ResolversFile, "resolvers", "r", "", "file containing resolver list for nuclei"),
		flagSet.BoolVarP(&generators.Options.SystemResolvers, "system-resolvers", "sr", false, "use system DNS resolving as error fallback"),
		flagSet.BoolVar(&generators.Options.OfflineHTTP, "passive", false, "enable passive HTTP response processing mode"),
		flagSet.BoolVarP(&generators.Options.EnvironmentVariables, "env-vars", "ev", false, "enable environment variables to be used in template"),
		flagSet.StringVarP(&generators.Options.ClientCertFile, "client-cert", "cc", "", "client certificate file (PEM-encoded) used for authenticating against scanned hosts"),
		flagSet.StringVarP(&generators.Options.ClientKeyFile, "client-key", "ck", "", "client key file (PEM-encoded) used for authenticating against scanned hosts"),
		flagSet.StringVarP(&generators.Options.ClientCAFile, "client-ca", "ca", "", "client certificate authority file (PEM-encoded) used for authenticating against scanned hosts"),
		flagSet.BoolVarP(&generators.Options.ShowMatchLine, "show-match-line", "sml", false, "show match lines for file templates, works with extractors only"),
		flagSet.BoolVar(&generators.Options.ZTLS, "ztls", false, "use ztls library with autofallback to standard one for tls13"),
		flagSet.StringVar(&generators.Options.SNI, "sni", "", "tls sni hostname to use (default: input domain name)"),
	)

	flagSet.CreateGroup("interactsh", "interactsh",
		flagSet.StringVarP(&generators.Options.InteractshURL, "interactsh-server", "iserver", "", fmt.Sprintf("interactsh server url for self-hosted instance (default: %s)", client.DefaultOptions.ServerURL)),
		flagSet.StringVarP(&generators.Options.InteractshToken, "interactsh-token", "itoken", "", "authentication token for self-hosted interactsh server"),
		flagSet.IntVar(&generators.Options.InteractionsCacheSize, "interactions-cache-size", 5000, "number of requests to keep in the interactions cache"),
		flagSet.IntVar(&generators.Options.InteractionsEviction, "interactions-eviction", 60, "number of seconds to wait before evicting requests from cache"),
		flagSet.IntVar(&generators.Options.InteractionsPollDuration, "interactions-poll-duration", 5, "number of seconds to wait before each interaction poll request"),
		flagSet.IntVar(&generators.Options.InteractionsCoolDownPeriod, "interactions-cooldown-period", 5, "extra time for interaction polling before exiting"),
		flagSet.BoolVarP(&generators.Options.NoInteractsh, "no-interactsh", "ni", false, "disable interactsh server for OAST testing, exclude OAST based templates"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&generators.Options.RateLimit, "rate-limit", "rl", 150, "maximum number of requests to send per second"),
		flagSet.IntVarP(&generators.Options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "maximum number of requests to send per minute"),
		flagSet.IntVarP(&generators.Options.BulkSize, "bulk-size", "bs", 25, "maximum number of hosts to be analyzed in parallel per template"),
		flagSet.IntVarP(&generators.Options.TemplateThreads, "concurrency", "c", 25, "maximum number of templates to be executed in parallel"),
		flagSet.IntVarP(&generators.Options.HeadlessBulkSize, "headless-bulk-size", "hbs", 10, "maximum number of headless hosts to be analyzed in parallel per template"),
		flagSet.IntVarP(&generators.Options.HeadlessTemplateThreads, "headless-concurrency", "headc", 10, "maximum number of headless templates to be executed in parallel"),
	)

	flagSet.CreateGroup("optimization", "Optimizations",
		flagSet.IntVar(&generators.Options.Timeout, "timeout", 5, "time to wait in seconds before timeout"),
		flagSet.IntVar(&generators.Options.Retries, "retries", 1, "number of times to retry a failed request"),
		flagSet.BoolVarP(&generators.Options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "leave default HTTP/HTTPS ports (eg. host:80,host:443"),
		flagSet.IntVarP(&generators.Options.MaxHostError, "max-host-error", "mhe", 30, "max errors for a host before skipping from scan"),
		flagSet.BoolVar(&generators.Options.Project, "project", false, "use a project folder to avoid sending same request multiple times"),
		flagSet.StringVar(&generators.Options.ProjectPath, "project-path", os.TempDir(), "set a specific project path"),
		flagSet.BoolVarP(&generators.Options.StopAtFirstMatch, "stop-at-first-path", "spm", false, "stop processing HTTP requests after the first match (may break template/workflow logic)"),
		flagSet.BoolVar(&generators.Options.Stream, "stream", false, "stream mode - start elaborating without sorting the input"),
		flagSet.DurationVarP(&generators.Options.InputReadTimeout, "input-read-timeout", "irt", time.Duration(3*time.Minute), "timeout on input read"),
		flagSet.BoolVar(&generators.Options.DisableStdin, "no-stdin", false, "Disable Stdin processing"),
	)

	flagSet.CreateGroup("headless", "Headless",
		flagSet.BoolVar(&generators.Options.Headless, "headless", false, "enable templates that require headless browser support (root user on linux will disable sandbox)"),
		flagSet.IntVar(&generators.Options.PageTimeout, "page-timeout", 20, "seconds to wait for each page in headless mode"),
		flagSet.BoolVarP(&generators.Options.ShowBrowser, "show-browser", "sb", false, "show the browser on the screen when running templates with headless mode"),
		flagSet.BoolVarP(&generators.Options.UseInstalledChrome, "system-chrome", "sc", false, "Use local installed chrome browser instead of nuclei installed"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&generators.Options.Debug, "debug", false, "show all requests and responses"),
		flagSet.BoolVarP(&generators.Options.DebugRequests, "debug-req", "dreq", false, "show all sent requests"),
		flagSet.BoolVarP(&generators.Options.DebugResponse, "debug-resp", "dresp", false, "show all received responses"),
		flagSet.NormalizedOriginalStringSliceVarP(&generators.Options.Proxy, "proxy", "p", []string{}, "list of http/socks5 proxy to use (comma separated or file input)"),
		flagSet.BoolVarP(&generators.Options.ProxyInternal, "proxy-internal", "pi", false, "proxy all internal requests"),
		flagSet.StringVarP(&generators.Options.TraceLogFile, "trace-log", "tlog", "", "file to write sent requests trace log"),
		flagSet.StringVarP(&generators.Options.ErrorLogFile, "error-log", "elog", "", "file to write sent requests error log"),
		flagSet.BoolVar(&generators.Options.Version, "version", false, "show nuclei version"),
		flagSet.BoolVarP(&generators.Options.HangMonitor, "hang-monitor", "hm", false, "enable nuclei hang monitoring"),
		flagSet.BoolVarP(&generators.Options.Verbose, "verbose", "v", false, "show verbose output"),
		flagSet.BoolVar(&generators.Options.VerboseVerbose, "vv", false, "display templates loaded for scan"),
		flagSet.BoolVarP(&generators.Options.EnablePprof, "enable-pprof", "ep", false, "enable pprof debugging server"),
		flagSet.BoolVarP(&generators.Options.TemplatesVersion, "templates-version", "tv", false, "shows the version of the installed nuclei-templates"),
		flagSet.BoolVarP(&generators.Options.HealthCheck, "health-check", "hc", false, "run diagnostic check up"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVar(&generators.Options.UpdateNuclei, "update", false, "update nuclei engine to the latest released version"),
		flagSet.BoolVarP(&generators.Options.UpdateTemplates, "update-templates", "ut", false, "update nuclei-templates to latest released version"),
		flagSet.StringVarP(&generators.Options.TemplatesDirectory, "update-directory", "ud", "", "overwrite the default directory to install nuclei-templates"),
		flagSet.BoolVarP(&generators.Options.NoUpdateTemplates, "disable-update-check", "duc", false, "disable automatic nuclei/templates update check"),
	)

	flagSet.CreateGroup("stats", "Statistics",
		flagSet.BoolVar(&generators.Options.EnableProgressBar, "stats", false, "display statistics about the running scan"),
		flagSet.BoolVarP(&generators.Options.StatsJSON, "stats-json", "sj", false, "write statistics data to an output file in JSONL(ines) format"),
		flagSet.IntVarP(&generators.Options.StatsInterval, "stats-interval", "si", 5, "number of seconds to wait between showing a statistics update"),
		flagSet.BoolVarP(&generators.Options.Metrics, "metrics", "m", false, "expose nuclei metrics on a port"),
		flagSet.IntVarP(&generators.Options.MetricsPort, "metrics-port", "mp", 9092, "port to expose nuclei metrics on"),
	)

	_ = flagSet.Parse()

	if generators.Options.LeaveDefaultPorts {
		http.LeaveDefaultPorts = true
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
		cfgFileFolder := filepath.Dir(cfgFile)
		if err := config.OverrideIgnoreFilePath(cfgFileFolder); err != nil {
			gologger.Warning().Msgf("Could not read ignore file from custom path: %s\n", err)
		}
	}
	cleanupOldResumeFiles()
}

func cleanupOldResumeFiles() {
	root, err := config.GetConfigDir()
	if err != nil {
		return
	}
	filter := fileutil.FileFilters{
		OlderThan: 24 * time.Hour * 10, // cleanup on the 10th day
		Prefix:    "resume-",
	}
	_ = fileutil.DeleteFilesOlderThan(root, filter)
}
