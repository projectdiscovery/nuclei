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

	nucleiRunner.RunEnumeration()
	nucleiRunner.Close()
}

func readConfig() {
	home, _ := os.UserHomeDir()
	templatesDirectory := path.Join(home, "nuclei-templates")

	set := goflags.New()
	set.SetDescription(`Nuclei is a fast tool for configurable targeted scanning 
based on templates offering massive extensibility and ease of use.`)
	set.StringVar(&cfgFile, "config", "", "Nuclei configuration file")
	set.BoolVar(&options.Metrics, "metrics", false, "Expose nuclei metrics on a port")
	set.IntVar(&options.MetricsPort, "metrics-port", 9092, "Port to expose nuclei metrics on")
	set.StringVar(&options.Target, "target", "", "Target is a single target to scan using template")
	set.StringSliceVarP(&options.Templates, "templates", "t", []string{}, "Template input dir/file/files to run on host. Can be used multiple times. Supports globbing.")
	set.StringSliceVar(&options.ExcludedTemplates, "exclude", []string{}, "Template input dir/file/files to exclude. Can be used multiple times. Supports globbing.")
	set.StringVarP(&options.Normalized, "normalized", "n", "", "Normalized requests input dir/file/files.")
	set.StringVar(&options.NormalizedOutput, "normalized-output", "", "Optional File to write internal normalized format representation to")
	set.StringSliceVar(&options.Severity, "severity", []string{}, "Filter templates based on their severity and only run the matching ones. Comma-separated values can be used to specify multiple severities.")
	set.StringVarP(&options.Targets, "list", "l", "", "List of URLs to run templates on")
	set.StringVarP(&options.Output, "output", "o", "", "File to write output to (optional)")
	set.StringVar(&options.ProxyURL, "proxy-url", "", "URL of the proxy server")
	set.StringVar(&options.ProxySocksURL, "proxy-socks-url", "", "URL of the proxy socks server")
	set.BoolVar(&options.Silent, "silent", false, "Show only results in output")
	set.BoolVar(&options.Version, "version", false, "Show version of nuclei")
	set.BoolVarP(&options.Verbose, "verbose", "v", false, "Show Verbose output")
	set.BoolVar(&options.NoColor, "no-color", false, "Disable colors in output")
	set.IntVar(&options.Timeout, "timeout", 5, "Time to wait in seconds before timeout")
	set.IntVar(&options.Retries, "retries", 1, "Number of times to retry a failed request")
	set.BoolVar(&options.RandomAgent, "random-agent", false, "Use randomly selected HTTP User-Agent header value")
	set.StringSliceVarP(&options.CustomHeaders, "header", "H", []string{}, "Custom Header.")
	set.BoolVar(&options.Debug, "debug", false, "Allow debugging of request/responses")
	set.BoolVar(&options.DebugRequests, "debug-req", false, "Allow debugging of request")
	set.BoolVar(&options.DebugResponse, "debug-resp", false, "Allow debugging of response")
	set.BoolVar(&options.UpdateTemplates, "update-templates", false, "Update Templates updates the installed templates (optional)")
	set.StringVar(&options.TraceLogFile, "trace-log", "", "File to write sent requests trace log")
	set.StringVar(&options.TemplatesDirectory, "update-directory", templatesDirectory, "Directory to use for storing nuclei-templates")
	set.BoolVar(&options.JSON, "json", false, "Write json output to files")
	set.BoolVar(&options.JSONRequests, "include-rr", false, "Write requests/responses for matches in JSON output")
	set.BoolVar(&options.EnableProgressBar, "stats", false, "Display stats of the running scan")
	set.BoolVar(&options.TemplateList, "tl", false, "List available templates")
	set.IntVar(&options.RateLimit, "rate-limit", 150, "Rate-Limit (maximum requests/second")
	set.BoolVar(&options.StopAtFirstMatch, "stop-at-first-match", false, "Stop processing http requests at first match (this may break template/workflow logic)")
	set.IntVar(&options.BulkSize, "bulk-size", 25, "Maximum Number of hosts analyzed in parallel per template")
	set.IntVarP(&options.TemplateThreads, "concurrency", "c", 10, "Maximum Number of templates executed in parallel")
	set.BoolVar(&options.Project, "project", false, "Use a project folder to avoid sending same request multiple times")
	set.StringVar(&options.ProjectPath, "project-path", "", "Use a user defined project folder, temporary folder is used if not specified but enabled")
	set.BoolVar(&options.NoMeta, "no-meta", false, "Don't display metadata for the matches")
	set.BoolVar(&options.TemplatesVersion, "templates-version", false, "Shows the installed nuclei-templates version")
	set.StringVar(&options.BurpCollaboratorBiid, "burp-collaborator-biid", "", "Burp Collaborator BIID")
	set.BoolVar(&options.Interactsh, "interactsh", false, "Use interactsh server for blind interaction polling")
	set.StringVar(&options.InteractshURL, "interactsh-url", "https://interact.sh", "Interactsh Server URL")
	set.IntVar(&options.InteractionsCacheSize, "interactions-cache-size", 5000, "Number of requests to keep in interactions cache")
	set.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "Number of seconds to wait before evicting requests from cache")
	set.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "Number of seconds before each interaction poll request")
	set.IntVar(&options.InteractionsColldownPeriod, "interactions-cooldown-period", 5, "Extra time for interaction polling before exiting")

	set.Parse()

	if cfgFile != "" {
		if err := set.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}
}
