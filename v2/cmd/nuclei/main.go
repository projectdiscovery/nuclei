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
	set.StringVarP(&options.Target, "target", "u", "", "Single target to scan")
	set.StringSliceVarP(&options.Templates, "templates", "t", []string{}, "Templates to run, supports single and multiple templates using directory.")
	set.StringSliceVar(&options.ExcludedTemplates, "exclude", []string{}, "Templates to exclude, supports single and multiple templates using directory.")
	set.StringVarP(&options.Normalized, "normalized", "n", "", "Normalized requests input dir/file/files.")
	set.StringVar(&options.NormalizedOutput, "normalized-output", "", "Optional File to write internal normalized format representation to")
	set.StringSliceVar(&options.Severity, "severity", []string{}, "Templates to run based on severity, supports single and multiple severity.")
	set.StringVarP(&options.Targets, "list", "l", "", "List of URLs to run templates on")
	set.StringVarP(&options.Output, "output", "o", "", "File to write output to (optional)")
	set.StringVar(&options.ProxyURL, "proxy-url", "", "URL of the proxy server")
	set.StringVar(&options.ProxySocksURL, "proxy-socks-url", "", "URL of the proxy socks server")
	set.BoolVar(&options.Silent, "silent", false, "Show only results in output")
	set.BoolVar(&options.Version, "version", false, "Show version of nuclei")
	set.BoolVarP(&options.Verbose, "verbose", "v", false, "Show verbose output")
	set.BoolVar(&options.NoColor, "no-color", false, "Disable colors in output")
	set.IntVar(&options.Timeout, "timeout", 5, "Time to wait in seconds before timeout")
	set.IntVar(&options.Retries, "retries", 1, "Number of times to retry a failed request")
	set.BoolVarP(&options.RandomAgent, "random-agent", "ra", false, "Use randomly selected HTTP User-Agent header value")
	set.StringSliceVarP(&options.CustomHeaders, "header", "H", []string{}, "Custom Header.")
	set.BoolVar(&options.Debug, "debug", false, "Debugging request and responses")
	set.BoolVar(&options.DebugRequests, "debug-req", false, "Debugging request")
	set.BoolVar(&options.DebugResponse, "debug-resp", false, "Debugging response")
	set.BoolVarP(&options.UpdateTemplates, "update-templates", "ut", false, "Download / updates nuclei community templates")
	set.StringVar(&options.TraceLogFile, "trace-log", "", "File to write sent requests trace log")
	set.StringVarP(&options.TemplatesDirectory, "update-directory", "ud", templatesDirectory, "Directory storing nuclei-templates")
	set.BoolVar(&options.JSON, "json", false, "Write json output to files")
	set.BoolVar(&options.JSONRequests, "include-rr", false, "Write requests/responses for matches in JSON output")
	set.BoolVar(&options.EnableProgressBar, "stats", false, "Display stats of the running scan")
	set.BoolVar(&options.TemplateList, "tl", false, "List available templates")
	set.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "Maximum requests to send per second")
	set.BoolVarP(&options.StopAtFirstMatch, "stop-at-first-path", "spm", false, "Stop processing http requests at first match (this may break template/workflow logic)")
	set.IntVarP(&options.BulkSize, "bulk-size", "bs", 25, "Maximum Number of hosts analyzed in parallel per template")
	set.IntVarP(&options.TemplateThreads, "concurrency", "c", 10, "Maximum Number of templates executed in parallel")
	set.BoolVar(&options.Project, "project", false, "Use a project folder to avoid sending same request multiple times")
	set.StringVar(&options.ProjectPath, "project-path", "", "Use a user defined project folder, temporary folder is used if not specified but enabled")
	set.BoolVarP(&options.NoMeta, "no-meta", "nm", false, "Don't display metadata for the matches")
	set.BoolVarP(&options.TemplatesVersion, "templates-version", "tv", false, "Shows the installed nuclei-templates version")
	set.BoolVar(&options.Interactsh, "interactsh", false, "Use interactsh server for blind interaction polling")
	set.StringVar(&options.InteractshURL, "interactsh-url", "https://interact.sh", "Interactsh Server URL")
	set.IntVar(&options.InteractionsCacheSize, "interactions-cache-size", 5000, "Number of requests to keep in interactions cache")
	set.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "Number of seconds to wait before evicting requests from cache")
	set.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "Number of seconds before each interaction poll request")
	set.IntVar(&options.InteractionsColldownPeriod, "interactions-cooldown-period", 5, "Extra time for interaction polling before exiting")
	set.BoolVar(&options.OfflineHTTP, "passive", false, "Enable Passive HTTP response processing mode")
	set.StringVarP(&options.BurpCollaboratorBiid, "burp-collaborator-biid", "biid", "", "Burp Collaborator BIID")
	set.StringSliceVar(&options.Tags, "tags", []string{}, "Tags to execute templates for")
	_ = set.Parse()

	if cfgFile != "" {
		if err := set.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}
}
