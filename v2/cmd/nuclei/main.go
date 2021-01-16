package main

import (
	"os"
	"path"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	cfgFile string

	options = &types.Options{}
	rootCmd = &cobra.Command{
		Use:   "nuclei",
		Short: "Nuclei is a fast and extensible security scanner",
		Long: `Nuclei is a fast tool for configurable targeted scanning 
based on templates offering massive extensibility and ease of use.`,
		Run: func(cmd *cobra.Command, args []string) {
			mergeViperConfiguration(cmd)

			runner.ParseOptions(options)

			nucleiRunner, err := runner.New(options)
			if err != nil {
				gologger.Fatal().Msgf("Could not create runner: %s\n", err)
			}

			nucleiRunner.RunEnumeration()
			nucleiRunner.Close()
		},
	}
)

func main() {
	rootCmd.Execute()
}

// mergeViperConfiguration merges the flag configuration with viper file.
func mergeViperConfiguration(cmd *cobra.Command) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed && viper.IsSet(f.Name) {
			switch p := viper.Get(f.Name).(type) {
			case []interface{}:
				for _, item := range p {
					cmd.PersistentFlags().Set(f.Name, cast.ToString(item))
				}
			default:
				cmd.PersistentFlags().Set(f.Name, viper.GetString(f.Name))
			}
		}
	})
}

func init() {
	home, _ := os.UserHomeDir()
	templatesDirectory := path.Join(home, "nuclei-templates")

	cobra.OnInitialize(func() {
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
			if err := viper.ReadInConfig(); err != nil {
				gologger.Fatal().Msgf("Could not read config: %s\n", err)
			}
		}
	})
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "Nuclei config file (default is $HOME/.nuclei.yaml)")
	rootCmd.PersistentFlags().BoolVar(&options.Metrics, "metrics", false, "Expose nuclei metrics on a port")
	rootCmd.PersistentFlags().IntVar(&options.MetricsPort, "metrics-port", 9092, "Port to expose nuclei metrics on")
	rootCmd.PersistentFlags().StringVar(&options.Target, "target", "", "Target is a single target to scan using template")
	rootCmd.PersistentFlags().StringSliceVarP(&options.Templates, "templates", "t", []string{}, "Template input dir/file/files to run on host. Can be used multiple times. Supports globbing.")
	rootCmd.PersistentFlags().StringSliceVar(&options.ExcludedTemplates, "exclude", []string{}, "Template input dir/file/files to exclude. Can be used multiple times. Supports globbing.")
	rootCmd.PersistentFlags().StringSliceVar(&options.Severity, "severity", []string{}, "Filter templates based on their severity and only run the matching ones. Comma-separated values can be used to specify multiple severities.")
	rootCmd.PersistentFlags().StringVarP(&options.Targets, "list", "l", "", "List of URLs to run templates on")
	rootCmd.PersistentFlags().StringVarP(&options.Output, "output", "o", "", "File to write output to (optional)")
	rootCmd.PersistentFlags().StringVar(&options.ProxyURL, "proxy-url", "", "URL of the proxy server")
	rootCmd.PersistentFlags().StringVar(&options.ProxySocksURL, "proxy-socks-url", "", "URL of the proxy socks server")
	rootCmd.PersistentFlags().BoolVar(&options.Silent, "silent", false, "Show only results in output")
	rootCmd.PersistentFlags().BoolVar(&options.Version, "version", false, "Show version of nuclei")
	rootCmd.PersistentFlags().BoolVarP(&options.Verbose, "verbose", "v", false, "Show Verbose output")
	rootCmd.PersistentFlags().BoolVar(&options.NoColor, "no-color", false, "Disable colors in output")
	rootCmd.PersistentFlags().IntVar(&options.Timeout, "timeout", 5, "Time to wait in seconds before timeout")
	rootCmd.PersistentFlags().IntVar(&options.Retries, "retries", 1, "Number of times to retry a failed request")
	rootCmd.PersistentFlags().BoolVar(&options.RandomAgent, "random-agent", false, "Use randomly selected HTTP User-Agent header value")
	rootCmd.PersistentFlags().StringSliceVarP(&options.CustomHeaders, "header", "H", []string{}, "Custom Header.")
	rootCmd.PersistentFlags().BoolVar(&options.Debug, "debug", false, "Allow debugging of request/responses")
	rootCmd.PersistentFlags().BoolVar(&options.DebugRequests, "debug-req", false, "Allow debugging of request")
	rootCmd.PersistentFlags().BoolVar(&options.DebugResponse, "debug-resp", false, "Allow debugging of response")
	rootCmd.PersistentFlags().BoolVar(&options.UpdateTemplates, "update-templates", false, "Update Templates updates the installed templates (optional)")
	rootCmd.PersistentFlags().StringVar(&options.TraceLogFile, "trace-log", "", "File to write sent requests trace log")
	rootCmd.PersistentFlags().StringVar(&options.TemplatesDirectory, "update-directory", templatesDirectory, "Directory to use for storing nuclei-templates")
	rootCmd.PersistentFlags().BoolVar(&options.JSON, "json", false, "Write json output to files")
	rootCmd.PersistentFlags().BoolVar(&options.JSONRequests, "include-rr", false, "Write requests/responses for matches in JSON output")
	rootCmd.PersistentFlags().BoolVar(&options.EnableProgressBar, "stats", false, "Display stats of the running scan")
	rootCmd.PersistentFlags().BoolVar(&options.TemplateList, "tl", false, "List available templates")
	rootCmd.PersistentFlags().IntVar(&options.RateLimit, "rate-limit", 150, "Rate-Limit (maximum requests/second")
	rootCmd.PersistentFlags().BoolVar(&options.StopAtFirstMatch, "stop-at-first-match", false, "Stop processing http requests at first match (this may break template/workflow logic)")
	rootCmd.PersistentFlags().IntVar(&options.BulkSize, "bulk-size", 25, "Maximum Number of hosts analyzed in parallel per template")
	rootCmd.PersistentFlags().IntVarP(&options.TemplateThreads, "concurrency", "c", 10, "Maximum Number of templates executed in parallel")
	rootCmd.PersistentFlags().BoolVar(&options.Project, "project", false, "Use a project folder to avoid sending same request multiple times")
	rootCmd.PersistentFlags().StringVar(&options.ProjectPath, "project-path", "", "Use a user defined project folder, temporary folder is used if not specified but enabled")
	rootCmd.PersistentFlags().BoolVar(&options.NoMeta, "no-meta", false, "Don't display metadata for the matches")
	rootCmd.PersistentFlags().BoolVar(&options.TemplatesVersion, "templates-version", false, "Shows the installed nuclei-templates version")
	rootCmd.PersistentFlags().StringVar(&options.BurpCollaboratorBiid, "burp-collaborator-biid", "", "Burp Collaborator BIID")
}
