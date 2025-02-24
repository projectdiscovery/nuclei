package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strings"
	"time"

	_pdcp "github.com/projectdiscovery/nuclei/v3/internal/pdcp"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	_ "github.com/projectdiscovery/utils/pprof"
	stringsutil "github.com/projectdiscovery/utils/strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/monitor"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	unitutils "github.com/projectdiscovery/utils/unit"
	updateutils "github.com/projectdiscovery/utils/update"
)

var (
	cfgFile         string
	templateProfile string
	memProfile      string // optional profile file path
	options         = &types.Options{}
)

func main() {
	// enables CLI specific configs mostly interactive behavior
	config.CurrentAppMode = config.AppModeCLI

	if err := runner.ConfigureOptions(); err != nil {
		gologger.Fatal().Msgf("Could not initialize options: %s\n", err)
	}
	_ = readConfig()

	if options.ListDslSignatures {
		gologger.Info().Msgf("The available custom DSL functions are:")
		fmt.Println(dsl.GetPrintableDslFunctionSignatures(options.NoColor))
		return
	}

	// sign the templates if requested - only glob syntax is supported
	if options.SignTemplates {
		// use parsed options when initializing signer instead of default options
		templates.UseOptionsForSigner(options)
		tsigner, err := signer.NewTemplateSigner(nil, nil) // will read from env , config or generate new keys
		if err != nil {
			gologger.Fatal().Msgf("couldn't initialize signer crypto engine: %s\n", err)
		}

		successCounter := 0
		errorCounter := 0
		for _, item := range options.Templates {
			err := filepath.WalkDir(item, func(iterItem string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() || !strings.HasSuffix(iterItem, extensions.YAML) {
					// skip non yaml files
					return nil
				}

				if err := templates.SignTemplate(tsigner, iterItem); err != nil {
					if err != templates.ErrNotATemplate {
						// skip warnings and errors as given items are not templates
						errorCounter++
						gologger.Error().Msgf("could not sign '%s': %s\n", iterItem, err)
					}
				} else {
					successCounter++
				}

				return nil
			})
			if err != nil {
				gologger.Error().Msgf("%s\n", err)
			}
		}
		gologger.Info().Msgf("All templates signatures were elaborated success=%d failed=%d\n", successCounter, errorCounter)
		return
	}

	// Profiling & tracing related code
	if memProfile != "" {
		memProfile = strings.TrimSuffix(memProfile, filepath.Ext(memProfile))

		createProfileFile := func(ext, profileType string) *os.File {
			f, err := os.Create(memProfile + ext)
			if err != nil {
				gologger.Fatal().Msgf("profile: could not create %s profile %q file: %v", profileType, f.Name(), err)
			}
			return f
		}

		memProfileFile := createProfileFile(".mem", "memory")
		cpuProfileFile := createProfileFile(".cpu", "CPU")
		traceFile := createProfileFile(".trace", "trace")

		oldMemProfileRate := runtime.MemProfileRate
		runtime.MemProfileRate = 4096

		// Start tracing
		if err := trace.Start(traceFile); err != nil {
			gologger.Fatal().Msgf("profile: could not start trace: %v", err)
		}

		// Start CPU profiling
		if err := pprof.StartCPUProfile(cpuProfileFile); err != nil {
			gologger.Fatal().Msgf("profile: could not start CPU profile: %v", err)
		}

		defer func() {
			// Start heap memory snapshot
			if err := pprof.WriteHeapProfile(memProfileFile); err != nil {
				gologger.Fatal().Msgf("profile: could not write memory profile: %v", err)
			}

			pprof.StopCPUProfile()
			memProfileFile.Close()
			traceFile.Close()
			trace.Stop()

			runtime.MemProfileRate = oldMemProfileRate

			gologger.Info().Msgf("CPU profile saved at %q", cpuProfileFile.Name())
			gologger.Info().Msgf("Memory usage snapshot saved at %q", memProfileFile.Name())
			gologger.Info().Msgf("Traced at %q", traceFile.Name())
		}()
	}

	runner.ParseOptions(options)

	if options.ScanUploadFile != "" {
		if err := runner.UploadResultsToCloud(options); err != nil {
			gologger.Fatal().Msgf("could not upload scan results to cloud dashboard: %s\n", err)
		}
		return
	}

	nucleiRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	if nucleiRunner == nil {
		return
	}

	if options.HangMonitor {
		stackMonitor := monitor.NewStackMonitor()
		cancel := stackMonitor.Start(10 * time.Second)
		defer cancel()
		stackMonitor.RegisterCallback(func(dumpID string) error {
			resumeFileName := fmt.Sprintf("crash-resume-file-%s.dump", dumpID)
			if options.EnableCloudUpload {
				gologger.Info().Msgf("Uploading scan results to cloud...")
			}
			nucleiRunner.Close()
			gologger.Info().Msgf("Creating resume file: %s\n", resumeFileName)
			err := nucleiRunner.SaveResumeConfig(resumeFileName)
			if err != nil {
				return errorutil.NewWithErr(err).Msgf("couldn't create crash resume file")
			}
			return nil
		})
	}

	// Setup graceful exits
	resumeFileName := types.DefaultResumeFilePath()
	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			if options.DASTServer {
				nucleiRunner.Close()
				os.Exit(1)
			}

			gologger.Info().Msgf("Attempting graceful shutdown...")
			if options.EnableCloudUpload {
				gologger.Info().Msgf("Uploading scan results to cloud...")
			}
			nucleiRunner.Close()
			if options.ShouldSaveResume() {
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
		if options.Validate {
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

func readConfig() *goflags.FlagSet {

	// when true updates nuclei binary to latest version
	var updateNucleiBinary bool
	var pdcpauth string
	var fuzzFlag bool

	flagSet := goflags.NewFlagSet()
	flagSet.CaseSensitive = true
	flagSet.SetDescription(`Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.`)

	/* TODO Important: The defined default values, especially for slice/array types are NOT DEFAULT VALUES, but rather implicit values to which the user input is appended.
	This can be very confusing and should be addressed
	*/

	flagSet.CreateGroup("input", "Target",
		flagSet.StringSliceVarP(&options.Targets, "target", "u", nil, "target URLs/hosts to scan", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.TargetsFilePath, "list", "l", "", "path to file containing a list of target URLs/hosts to scan (one per line)"),
		flagSet.StringSliceVarP(&options.ExcludeTargets, "exclude-hosts", "eh", nil, "hosts to exclude to scan from the input list (ip, cidr, hostname)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVar(&options.Resume, "resume", "", "resume scan using resume.cfg (clustering will be disabled)"),
		flagSet.BoolVarP(&options.ScanAllIPs, "scan-all-ips", "sa", false, "scan all the IP's associated with dns record"),
		flagSet.StringSliceVarP(&options.IPVersion, "ip-version", "iv", nil, "IP version to scan of hostname (4,6) - (default 4)", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("target-format", "Target-Format",
		flagSet.StringVarP(&options.InputFileMode, "input-mode", "im", "list", fmt.Sprintf("mode of input file (%v)", provider.SupportedInputFormats())),
		flagSet.BoolVarP(&options.FormatUseRequiredOnly, "required-only", "ro", false, "use only required fields in input format when generating requests"),
		flagSet.BoolVarP(&options.SkipFormatValidation, "skip-format-validation", "sfv", false, "skip format validation (like missing vars) when parsing input file"),
	)

	flagSet.CreateGroup("templates", "Templates",
		flagSet.BoolVarP(&options.NewTemplates, "new-templates", "nt", false, "run only new templates added in latest nuclei-templates release"),
		flagSet.StringSliceVarP(&options.NewTemplatesWithVersion, "new-templates-version", "ntv", nil, "run new templates added in specific version", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.AutomaticScan, "automatic-scan", "as", false, "automatic web scan using wappalyzer technology detection to tags mapping"),
		flagSet.StringSliceVarP(&options.Templates, "templates", "t", nil, "list of template or template directory to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.TemplateURLs, "template-url", "turl", nil, "template url or list containing template urls to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&options.AITemplatePrompt, "prompt", "ai", "", "generate and run template using ai prompt"),
		flagSet.StringSliceVarP(&options.Workflows, "workflows", "w", nil, "list of workflow or workflow directory to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.WorkflowURLs, "workflow-url", "wurl", nil, "workflow url or list containing workflow urls to run (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVar(&options.Validate, "validate", false, "validate the passed templates to nuclei"),
		flagSet.BoolVarP(&options.NoStrictSyntax, "no-strict-syntax", "nss", false, "disable strict syntax check on templates"),
		flagSet.BoolVarP(&options.TemplateDisplay, "template-display", "td", false, "displays the templates content"),
		flagSet.BoolVar(&options.TemplateList, "tl", false, "list all available templates"),
		flagSet.BoolVar(&options.TagList, "tgl", false, "list all available tags"),
		flagSet.StringSliceVarConfigOnly(&options.RemoteTemplateDomainList, "remote-template-domain", []string{"cloud.projectdiscovery.io"}, "allowed domain list to load remote templates from"),
		flagSet.BoolVar(&options.SignTemplates, "sign", false, "signs the templates with the private key defined in NUCLEI_SIGNATURE_PRIVATE_KEY env variable"),
		flagSet.BoolVar(&options.EnableCodeTemplates, "code", false, "enable loading code protocol-based templates"),
		flagSet.BoolVarP(&options.DisableUnsignedTemplates, "disable-unsigned-templates", "dut", false, "disable running unsigned templates or templates with mismatched signature"),
		flagSet.BoolVarP(&options.EnableSelfContainedTemplates, "enable-self-contained", "esc", false, "enable loading self-contained templates"),
		flagSet.BoolVarP(&options.EnableGlobalMatchersTemplates, "enable-global-matchers", "egm", false, "enable loading global matchers templates"),
		flagSet.BoolVar(&options.EnableFileTemplates, "file", false, "enable loading file templates"),
	)

	flagSet.CreateGroup("filters", "Filtering",
		flagSet.StringSliceVarP(&options.Authors, "author", "a", nil, "templates to run based on authors (comma-separated, file)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVar(&options.Tags, "tags", nil, "templates to run based on tags (comma-separated, file)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludeTags, "exclude-tags", "etags", nil, "templates to exclude based on tags (comma-separated, file)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.IncludeTags, "include-tags", "itags", nil, "tags to be executed even if they are excluded either by default or configuration", goflags.FileNormalizedStringSliceOptions), // TODO show default deny list
		flagSet.StringSliceVarP(&options.IncludeIds, "template-id", "id", nil, "templates to run based on template ids (comma-separated, file, allow-wildcard)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludeIds, "exclude-id", "eid", nil, "templates to exclude based on template ids (comma-separated, file)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.IncludeTemplates, "include-templates", "it", nil, "path to template file or directory to be executed even if they are excluded either by default or configuration", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludedTemplates, "exclude-templates", "et", nil, "path to template file or directory to exclude (comma-separated, file)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludeMatchers, "exclude-matchers", "em", nil, "template matchers to exclude in result", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.VarP(&options.Severities, "severity", "s", fmt.Sprintf("templates to run based on severity. Possible values: %s", severity.GetSupportedSeverities().String())),
		flagSet.VarP(&options.ExcludeSeverities, "exclude-severity", "es", fmt.Sprintf("templates to exclude based on severity. Possible values: %s", severity.GetSupportedSeverities().String())),
		flagSet.VarP(&options.Protocols, "type", "pt", fmt.Sprintf("templates to run based on protocol type. Possible values: %s", templateTypes.GetSupportedProtocolTypes())),
		flagSet.VarP(&options.ExcludeProtocols, "exclude-type", "ept", fmt.Sprintf("templates to exclude based on protocol type. Possible values: %s", templateTypes.GetSupportedProtocolTypes())),
		flagSet.StringSliceVarP(&options.IncludeConditions, "template-condition", "tc", nil, "templates to run based on expression condition", goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "output file to write found issues/vulnerabilities"),
		flagSet.BoolVarP(&options.StoreResponse, "store-resp", "sresp", false, "store all request/response passed through nuclei to output directory"),
		flagSet.StringVarP(&options.StoreResponseDir, "store-resp-dir", "srd", runner.DefaultDumpTrafficOutputFolder, "store all request/response passed through nuclei to custom directory"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display findings only"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable output content coloring (ANSI escape codes)"),
		flagSet.BoolVarP(&options.JSONL, "jsonl", "j", false, "write output in JSONL(ines) format"),
		flagSet.BoolVarP(&options.JSONRequests, "include-rr", "irr", true, "include request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only) [DEPRECATED use `-omit-raw`]"),
		flagSet.BoolVarP(&options.OmitRawRequests, "omit-raw", "or", false, "omit request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only)"),
		flagSet.BoolVarP(&options.OmitTemplate, "omit-template", "ot", false, "omit encoded template in the JSON, JSONL output"),
		flagSet.BoolVarP(&options.NoMeta, "no-meta", "nm", false, "disable printing result metadata in cli output"),
		flagSet.BoolVarP(&options.Timestamp, "timestamp", "ts", false, "enables printing timestamp in cli output"),
		flagSet.StringVarP(&options.ReportingDB, "report-db", "rdb", "", "nuclei reporting database (always use this to persist report data)"),
		flagSet.BoolVarP(&options.MatcherStatus, "matcher-status", "ms", false, "display match failure status"),
		flagSet.StringVarP(&options.MarkdownExportDirectory, "markdown-export", "me", "", "directory to export results in markdown format"),
		flagSet.StringVarP(&options.SarifExport, "sarif-export", "se", "", "file to export results in SARIF format"),
		flagSet.StringVarP(&options.JSONExport, "json-export", "je", "", "file to export results in JSON format"),
		flagSet.StringVarP(&options.JSONLExport, "jsonl-export", "jle", "", "file to export results in JSONL(ine) format"),
		flagSet.StringSliceVarP(&options.Redact, "redact", "rd", nil, "redact given list of keys from query parameter, request header and body", goflags.CommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the nuclei configuration file"),
		flagSet.StringVarP(&templateProfile, "profile", "tp", "", "template profile config file to run"),
		flagSet.BoolVarP(&options.ListTemplateProfiles, "profile-list", "tpl", false, "list community template profiles"),
		flagSet.BoolVarP(&options.FollowRedirects, "follow-redirects", "fr", false, "enable following redirects for http templates"),
		flagSet.BoolVarP(&options.FollowHostRedirects, "follow-host-redirects", "fhr", false, "follow redirects on the same host"),
		flagSet.IntVarP(&options.MaxRedirects, "max-redirects", "mr", 10, "max number of redirects to follow for http templates"),
		flagSet.BoolVarP(&options.DisableRedirects, "disable-redirects", "dr", false, "disable redirects for http templates"),
		flagSet.StringVarP(&options.ReportingConfig, "report-config", "rc", "", "nuclei reporting module configuration file"), // TODO merge into the config file or rename to issue-tracking
		flagSet.StringSliceVarP(&options.CustomHeaders, "header", "H", nil, "custom header/cookie to include in all http request in header:value format (cli, file)", goflags.FileStringSliceOptions),
		flagSet.RuntimeMapVarP(&options.Vars, "var", "V", nil, "custom vars in key=value format"),
		flagSet.StringVarP(&options.ResolversFile, "resolvers", "r", "", "file containing resolver list for nuclei"),
		flagSet.BoolVarP(&options.SystemResolvers, "system-resolvers", "sr", false, "use system DNS resolving as error fallback"),
		flagSet.BoolVarP(&options.DisableClustering, "disable-clustering", "dc", false, "disable clustering of requests"),
		flagSet.BoolVar(&options.OfflineHTTP, "passive", false, "enable passive HTTP response processing mode"),
		flagSet.BoolVarP(&options.ForceAttemptHTTP2, "force-http2", "fh2", false, "force http2 connection on requests"),
		flagSet.BoolVarP(&options.EnvironmentVariables, "env-vars", "ev", false, "enable environment variables to be used in template"),
		flagSet.StringVarP(&options.ClientCertFile, "client-cert", "cc", "", "client certificate file (PEM-encoded) used for authenticating against scanned hosts"),
		flagSet.StringVarP(&options.ClientKeyFile, "client-key", "ck", "", "client key file (PEM-encoded) used for authenticating against scanned hosts"),
		flagSet.StringVarP(&options.ClientCAFile, "client-ca", "ca", "", "client certificate authority file (PEM-encoded) used for authenticating against scanned hosts"),
		flagSet.BoolVarP(&options.ShowMatchLine, "show-match-line", "sml", false, "show match lines for file templates, works with extractors only"),
		flagSet.BoolVar(&options.ZTLS, "ztls", false, "use ztls library with autofallback to standard one for tls13 [Deprecated] autofallback to ztls is enabled by default"), //nolint:all
		flagSet.StringVar(&options.SNI, "sni", "", "tls sni hostname to use (default: input domain name)"),
		flagSet.DurationVarP(&options.DialerKeepAlive, "dialer-keep-alive", "dka", 0, "keep-alive duration for network requests."),
		flagSet.BoolVarP(&options.AllowLocalFileAccess, "allow-local-file-access", "lfa", false, "allows file (payload) access anywhere on the system"),
		flagSet.BoolVarP(&options.RestrictLocalNetworkAccess, "restrict-local-network-access", "lna", false, "blocks connections to the local / private network"),
		flagSet.StringVarP(&options.Interface, "interface", "i", "", "network interface to use for network scan"),
		flagSet.StringVarP(&options.AttackType, "attack-type", "at", "", "type of payload combinations to perform (batteringram,pitchfork,clusterbomb)"),
		flagSet.StringVarP(&options.SourceIP, "source-ip", "sip", "", "source ip address to use for network scan"),
		flagSet.IntVarP(&options.ResponseReadSize, "response-size-read", "rsr", 0, "max response size to read in bytes"),
		flagSet.IntVarP(&options.ResponseSaveSize, "response-size-save", "rss", unitutils.Mega, "max response size to read in bytes"),
		flagSet.CallbackVar(resetCallback, "reset", "reset removes all nuclei configuration and data files (including nuclei-templates)"),
		flagSet.BoolVarP(&options.TlsImpersonate, "tls-impersonate", "tlsi", false, "enable experimental client hello (ja3) tls randomization"),
		flagSet.StringVarP(&options.HttpApiEndpoint, "http-api-endpoint", "hae", "", "experimental http api endpoint"),
	)

	flagSet.CreateGroup("interactsh", "interactsh",
		flagSet.StringVarP(&options.InteractshURL, "interactsh-server", "iserver", "", fmt.Sprintf("interactsh server url for self-hosted instance (default: %s)", client.DefaultOptions.ServerURL)),
		flagSet.StringVarP(&options.InteractshToken, "interactsh-token", "itoken", "", "authentication token for self-hosted interactsh server"),
		flagSet.IntVar(&options.InteractionsCacheSize, "interactions-cache-size", 5000, "number of requests to keep in the interactions cache"),
		flagSet.IntVar(&options.InteractionsEviction, "interactions-eviction", 60, "number of seconds to wait before evicting requests from cache"),
		flagSet.IntVar(&options.InteractionsPollDuration, "interactions-poll-duration", 5, "number of seconds to wait before each interaction poll request"),
		flagSet.IntVar(&options.InteractionsCoolDownPeriod, "interactions-cooldown-period", 5, "extra time for interaction polling before exiting"),
		flagSet.BoolVarP(&options.NoInteractsh, "no-interactsh", "ni", false, "disable interactsh server for OAST testing, exclude OAST based templates"),
	)

	flagSet.CreateGroup("fuzzing", "Fuzzing",
		flagSet.StringVarP(&options.FuzzingType, "fuzzing-type", "ft", "", "overrides fuzzing type set in template (replace, prefix, postfix, infix)"),
		flagSet.StringVarP(&options.FuzzingMode, "fuzzing-mode", "fm", "", "overrides fuzzing mode set in template (multiple, single)"),
		flagSet.BoolVar(&fuzzFlag, "fuzz", false, "enable loading fuzzing templates (Deprecated: use -dast instead)"),
		flagSet.BoolVar(&options.DAST, "dast", false, "enable / run dast (fuzz) nuclei templates"),
		flagSet.BoolVarP(&options.DASTServer, "dast-server", "dts", false, "enable dast server mode (live fuzzing)"),
		flagSet.BoolVarP(&options.DASTReport, "dast-report", "dtr", false, "write dast scan report to file"),
		flagSet.StringVarP(&options.DASTServerToken, "dast-server-token", "dtst", "", "dast server token (optional)"),
		flagSet.StringVarP(&options.DASTServerAddress, "dast-server-address", "dtsa", "localhost:9055", "dast server address"),
		flagSet.BoolVarP(&options.DisplayFuzzPoints, "display-fuzz-points", "dfp", false, "display fuzz points in the output for debugging"),
		flagSet.IntVar(&options.FuzzParamFrequency, "fuzz-param-frequency", 10, "frequency of uninteresting parameters for fuzzing before skipping"),
		flagSet.StringVarP(&options.FuzzAggressionLevel, "fuzz-aggression", "fa", "low", "fuzzing aggression level controls payload count for fuzz (low, medium, high)"),
		flagSet.StringSliceVarP(&options.Scope, "fuzz-scope", "cs", nil, "in scope url regex to be followed by fuzzer", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.OutOfScope, "fuzz-out-scope", "cos", nil, "out of scope url regex to be excluded by fuzzer", goflags.FileCommaSeparatedStringSliceOptions),
	)

	flagSet.CreateGroup("uncover", "Uncover",
		flagSet.BoolVarP(&options.Uncover, "uncover", "uc", false, "enable uncover engine"),
		flagSet.StringSliceVarP(&options.UncoverQuery, "uncover-query", "uq", nil, "uncover search query", goflags.FileStringSliceOptions),
		flagSet.StringSliceVarP(&options.UncoverEngine, "uncover-engine", "ue", nil, fmt.Sprintf("uncover search engine (%s) (default shodan)", uncover.GetUncoverSupportedAgents()), goflags.FileStringSliceOptions),
		flagSet.StringVarP(&options.UncoverField, "uncover-field", "uf", "ip:port", "uncover fields to return (ip,port,host)"),
		flagSet.IntVarP(&options.UncoverLimit, "uncover-limit", "ul", 100, "uncover results to return"),
		flagSet.IntVarP(&options.UncoverRateLimit, "uncover-ratelimit", "ur", 60, "override ratelimit of engines with unknown ratelimit (default 60 req/min)"),
	)

	flagSet.CreateGroup("rate-limit", "Rate-Limit",
		flagSet.IntVarP(&options.RateLimit, "rate-limit", "rl", 150, "maximum number of requests to send per second"),
		flagSet.DurationVarP(&options.RateLimitDuration, "rate-limit-duration", "rld", time.Second, "maximum number of requests to send per second"),
		flagSet.IntVarP(&options.RateLimitMinute, "rate-limit-minute", "rlm", 0, "maximum number of requests to send per minute (DEPRECATED)"),
		flagSet.IntVarP(&options.BulkSize, "bulk-size", "bs", 25, "maximum number of hosts to be analyzed in parallel per template"),
		flagSet.IntVarP(&options.TemplateThreads, "concurrency", "c", 25, "maximum number of templates to be executed in parallel"),
		flagSet.IntVarP(&options.HeadlessBulkSize, "headless-bulk-size", "hbs", 10, "maximum number of headless hosts to be analyzed in parallel per template"),
		flagSet.IntVarP(&options.HeadlessTemplateThreads, "headless-concurrency", "headc", 10, "maximum number of headless templates to be executed in parallel"),
		flagSet.IntVarP(&options.JsConcurrency, "js-concurrency", "jsc", 120, "maximum number of javascript runtimes to be executed in parallel"),
		flagSet.IntVarP(&options.PayloadConcurrency, "payload-concurrency", "pc", 25, "max payload concurrency for each template"),
		flagSet.IntVarP(&options.ProbeConcurrency, "probe-concurrency", "prc", 50, "http probe concurrency with httpx"),
	)
	flagSet.CreateGroup("optimization", "Optimizations",
		flagSet.IntVar(&options.Timeout, "timeout", 10, "time to wait in seconds before timeout"),
		flagSet.IntVar(&options.Retries, "retries", 1, "number of times to retry a failed request"),
		flagSet.BoolVarP(&options.LeaveDefaultPorts, "leave-default-ports", "ldp", false, "leave default HTTP/HTTPS ports (eg. host:80,host:443)"),
		flagSet.IntVarP(&options.MaxHostError, "max-host-error", "mhe", 30, "max errors for a host before skipping from scan"),
		flagSet.StringSliceVarP(&options.TrackError, "track-error", "te", nil, "adds given error to max-host-error watchlist (standard, file)", goflags.FileStringSliceOptions),
		flagSet.BoolVarP(&options.NoHostErrors, "no-mhe", "nmhe", false, "disable skipping host from scan based on errors"),
		flagSet.BoolVar(&options.Project, "project", false, "use a project folder to avoid sending same request multiple times"),
		flagSet.StringVar(&options.ProjectPath, "project-path", os.TempDir(), "set a specific project path"),
		flagSet.BoolVarP(&options.StopAtFirstMatch, "stop-at-first-match", "spm", false, "stop processing HTTP requests after the first match (may break template/workflow logic)"),
		flagSet.BoolVar(&options.Stream, "stream", false, "stream mode - start elaborating without sorting the input"),
		flagSet.EnumVarP(&options.ScanStrategy, "scan-strategy", "ss", goflags.EnumVariable(0), "strategy to use while scanning(auto/host-spray/template-spray)", goflags.AllowdTypes{
			scanstrategy.Auto.String():          goflags.EnumVariable(0),
			scanstrategy.HostSpray.String():     goflags.EnumVariable(1),
			scanstrategy.TemplateSpray.String(): goflags.EnumVariable(2),
		}),
		flagSet.DurationVarP(&options.InputReadTimeout, "input-read-timeout", "irt", time.Duration(3*time.Minute), "timeout on input read"),
		flagSet.BoolVarP(&options.DisableHTTPProbe, "no-httpx", "nh", false, "disable httpx probing for non-url input"),
		flagSet.BoolVar(&options.DisableStdin, "no-stdin", false, "disable stdin processing"),
	)

	flagSet.CreateGroup("headless", "Headless",
		flagSet.BoolVar(&options.Headless, "headless", false, "enable templates that require headless browser support (root user on Linux will disable sandbox)"),
		flagSet.IntVar(&options.PageTimeout, "page-timeout", 20, "seconds to wait for each page in headless mode"),
		flagSet.BoolVarP(&options.ShowBrowser, "show-browser", "sb", false, "show the browser on the screen when running templates with headless mode"),
		flagSet.StringSliceVarP(&options.HeadlessOptionalArguments, "headless-options", "ho", nil, "start headless chrome with additional options", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.UseInstalledChrome, "system-chrome", "sc", false, "use local installed Chrome browser instead of nuclei installed"),
		flagSet.BoolVarP(&options.ShowActions, "list-headless-action", "lha", false, "list available headless actions"),
	)

	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVar(&options.Debug, "debug", false, "show all requests and responses"),
		flagSet.BoolVarP(&options.DebugRequests, "debug-req", "dreq", false, "show all sent requests"),
		flagSet.BoolVarP(&options.DebugResponse, "debug-resp", "dresp", false, "show all received responses"),
		flagSet.StringSliceVarP(&options.Proxy, "proxy", "p", nil, "list of http/socks5 proxy to use (comma separated or file input)", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.ProxyInternal, "proxy-internal", "pi", false, "proxy all internal requests"),
		flagSet.BoolVarP(&options.ListDslSignatures, "list-dsl-function", "ldf", false, "list all supported DSL function signatures"),
		flagSet.StringVarP(&options.TraceLogFile, "trace-log", "tlog", "", "file to write sent requests trace log"),
		flagSet.StringVarP(&options.ErrorLogFile, "error-log", "elog", "", "file to write sent requests error log"),
		flagSet.CallbackVar(printVersion, "version", "show nuclei version"),
		flagSet.BoolVarP(&options.HangMonitor, "hang-monitor", "hm", false, "enable nuclei hang monitoring"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "show verbose output"),
		flagSet.StringVar(&memProfile, "profile-mem", "", "generate memory (heap) profile & trace files"),
		flagSet.BoolVar(&options.VerboseVerbose, "vv", false, "display templates loaded for scan"),
		flagSet.BoolVarP(&options.ShowVarDump, "show-var-dump", "svd", false, "show variables dump for debugging"),
		flagSet.IntVarP(&options.VarDumpLimit, "var-dump-limit", "vdl", 255, "limit the number of characters displayed in var dump"),
		flagSet.BoolVarP(&options.EnablePprof, "enable-pprof", "ep", false, "enable pprof debugging server"),
		flagSet.CallbackVarP(printTemplateVersion, "templates-version", "tv", "shows the version of the installed nuclei-templates"),
		flagSet.BoolVarP(&options.HealthCheck, "health-check", "hc", false, "run diagnostic check up"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.BoolVarP(&updateNucleiBinary, "update", "up", false, "update nuclei engine to the latest released version"),
		flagSet.BoolVarP(&options.UpdateTemplates, "update-templates", "ut", false, "update nuclei-templates to latest released version"),
		flagSet.StringVarP(&options.NewTemplatesDirectory, "update-template-dir", "ud", "", "custom directory to install / update nuclei-templates"),
		flagSet.CallbackVarP(disableUpdatesCallback, "disable-update-check", "duc", "disable automatic nuclei/templates update check"),
	)

	flagSet.CreateGroup("stats", "Statistics",
		flagSet.BoolVar(&options.EnableProgressBar, "stats", false, "display statistics about the running scan"),
		flagSet.BoolVarP(&options.StatsJSON, "stats-json", "sj", false, "display statistics in JSONL(ines) format"),
		flagSet.IntVarP(&options.StatsInterval, "stats-interval", "si", 5, "number of seconds to wait between showing a statistics update"),
		flagSet.IntVarP(&options.MetricsPort, "metrics-port", "mp", 9092, "port to expose nuclei metrics on"),
		flagSet.BoolVarP(&options.HTTPStats, "http-stats", "hps", false, "enable http status capturing (experimental)"),
	)

	flagSet.CreateGroup("cloud", "Cloud",
		flagSet.DynamicVar(&pdcpauth, "auth", "true", "configure projectdiscovery cloud (pdcp) api key"),
		flagSet.StringVarP(&options.TeamID, "team-id", "tid", _pdcp.TeamIDEnv, "upload scan results to given team id (optional)"),
		flagSet.BoolVarP(&options.EnableCloudUpload, "cloud-upload", "cup", false, "upload scan results to pdcp dashboard [DEPRECATED use -dashboard]"),
		flagSet.StringVarP(&options.ScanID, "scan-id", "sid", "", "upload scan results to existing scan id (optional)"),
		flagSet.StringVarP(&options.ScanName, "scan-name", "sname", "", "scan name to set (optional)"),
		flagSet.BoolVarP(&options.EnableCloudUpload, "dashboard", "pd", false, "upload / view nuclei results in projectdiscovery cloud (pdcp) UI dashboard"),
		flagSet.StringVarP(&options.ScanUploadFile, "dashboard-upload", "pdu", "", "upload / view nuclei results file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard"),
	)

	flagSet.CreateGroup("Authentication", "Authentication",
		flagSet.StringSliceVarP(&options.SecretsFile, "secret-file", "sf", nil, "path to config file containing secrets for nuclei authenticated scan", goflags.CommaSeparatedStringSliceOptions),
		flagSet.BoolVarP(&options.PreFetchSecrets, "prefetch-secrets", "ps", false, "prefetch secrets from the secrets file"),
	)

	flagSet.SetCustomHelpText(`EXAMPLES:
Run nuclei on single host:
	$ nuclei -target example.com

Run nuclei with specific template directories:
	$ nuclei -target example.com -t http/cves/ -t ssl

Run nuclei against a list of hosts:
	$ nuclei -list hosts.txt

Run nuclei with a JSON output:
	$ nuclei -target example.com -json-export output.json

Run nuclei with sorted Markdown outputs (with environment variables):
	$ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

Additional documentation is available at: https://docs.nuclei.sh/getting-started/running
	`)

	// nuclei has multiple migrations
	// ex: resume.cfg moved to platform standard cache dir from config dir
	// ex: config.yaml moved to platform standard config dir from linux specific config dir
	// and hence it will be attempted in config package during init
	goflags.DisableAutoConfigMigration = true
	_ = flagSet.Parse()

	// when fuzz flag is enabled, set the dast flag to true
	if fuzzFlag {
		// backwards compatibility for fuzz flag
		options.DAST = true
	}

	// All cloud-based templates depend on both code and self-contained templates.
	if options.EnableCodeTemplates {
		options.EnableSelfContainedTemplates = true
	}

	// api key hierarchy: cli flag > env var > .pdcp/credential file
	if pdcpauth == "true" {
		runner.AuthWithPDCP()
	} else if len(pdcpauth) == 36 {
		ph := pdcp.PDCPCredHandler{}
		if _, err := ph.GetCreds(); err == pdcp.ErrNoCreds {
			apiServer := env.GetEnvOrDefault("PDCP_API_SERVER", pdcp.DefaultApiServer)
			if validatedCreds, err := ph.ValidateAPIKey(pdcpauth, apiServer, config.BinaryName); err == nil {
				_ = ph.SaveCreds(validatedCreds)
			}
		}
	}

	// guard cloud services with credentials
	if options.AITemplatePrompt != "" {
		h := &pdcp.PDCPCredHandler{}
		_, err := h.GetCreds()
		if err != nil {
			gologger.Fatal().Msg("To utilize the `-ai` flag, please configure your API key with the `-auth` flag or set the `PDCP_API_KEY` environment variable")
		}
	}

	gologger.DefaultLogger.SetTimestamp(options.Timestamp, levels.LevelDebug)

	if options.VerboseVerbose {
		// hide release notes if silent mode is enabled
		installer.HideReleaseNotes = false
	}

	if options.Timeout > 30 {
		// default github binary/template download timeout is 30 sec
		updateutils.DownloadUpdateTimeout = time.Duration(options.Timeout) * time.Second
	}
	if updateNucleiBinary {
		runner.NucleiToolUpdateCallback()
	}

	if options.LeaveDefaultPorts {
		http.LeaveDefaultPorts = true
	}
	if customConfigDir := os.Getenv(config.NucleiConfigDirEnv); customConfigDir != "" {
		config.DefaultConfig.SetConfigDir(customConfigDir)
		readFlagsConfig(flagSet)
	}
	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}
	if options.NewTemplatesDirectory != "" {
		config.DefaultConfig.SetTemplatesDir(options.NewTemplatesDirectory)
	}

	defaultProfilesPath := filepath.Join(config.DefaultConfig.GetTemplateDir(), "profiles")
	if templateProfile != "" {
		if filepath.Ext(templateProfile) == "" {
			if tp := findProfilePathById(templateProfile, defaultProfilesPath); tp != "" {
				templateProfile = tp
			} else {
				gologger.Fatal().Msgf("'%s' is not a profile-id or profile path", templateProfile)
			}
		}
		if !filepath.IsAbs(templateProfile) {
			if filepath.Dir(templateProfile) == "profiles" {
				defaultProfilesPath = filepath.Join(config.DefaultConfig.GetTemplateDir())
			}
			currentDir, err := os.Getwd()
			if err == nil && fileutil.FileExists(filepath.Join(currentDir, templateProfile)) {
				templateProfile = filepath.Join(currentDir, templateProfile)
			} else {
				templateProfile = filepath.Join(defaultProfilesPath, templateProfile)
			}
		}
		if !fileutil.FileExists(templateProfile) {
			gologger.Fatal().Msgf("given template profile file '%s' does not exist", templateProfile)
		}
		if err := flagSet.MergeConfigFile(templateProfile); err != nil {
			gologger.Fatal().Msgf("Could not read template profile: %s\n", err)
		}
	}

	if len(options.SecretsFile) > 0 {
		for _, secretFile := range options.SecretsFile {
			if !fileutil.FileExists(secretFile) {
				gologger.Fatal().Msgf("given secrets file '%s' does not exist", options.SecretsFile)
			}
		}
	}

	cleanupOldResumeFiles()
	return flagSet
}

// cleanupOldResumeFiles cleans up resume files older than 10 days.
func cleanupOldResumeFiles() {
	root := config.DefaultConfig.GetCacheDir()
	filter := fileutil.FileFilters{
		OlderThan: 24 * time.Hour * 10, // cleanup on the 10th day
		Prefix:    "resume-",
	}
	_ = fileutil.DeleteFilesOlderThan(root, filter)
}

// readFlagsConfig reads the config file from the default config dir and copies it to the current config dir.
func readFlagsConfig(flagset *goflags.FlagSet) {
	// check if config.yaml file exists
	defaultCfgFile, err := flagset.GetConfigFilePath()
	if err != nil {
		// something went wrong either dir is not readable or something else went wrong upstream in `goflags`
		// warn and exit in this case
		gologger.Warning().Msgf("Could not read config file: %s\n", err)
		return
	}
	cfgFile := config.DefaultConfig.GetFlagsConfigFilePath()
	if !fileutil.FileExists(cfgFile) {
		if !fileutil.FileExists(defaultCfgFile) {
			// if default config does not exist, warn and exit
			gologger.Warning().Msgf("missing default config file : %s", defaultCfgFile)
			return
		}
		// if does not exist copy it from the default config
		if err = fileutil.CopyFile(defaultCfgFile, cfgFile); err != nil {
			gologger.Warning().Msgf("Could not copy config file: %s\n", err)
		}
		return
	}
	// if config file exists, merge it with the default config
	if err = flagset.MergeConfigFile(cfgFile); err != nil {
		gologger.Warning().Msgf("failed to merge configfile with flags got: %s\n", err)
	}
}

// disableUpdatesCallback disables the update check.
func disableUpdatesCallback() {
	config.DefaultConfig.DisableUpdateCheck()
}

// printVersion prints the nuclei version and exits.
func printVersion() {
	gologger.Info().Msgf("Nuclei Engine Version: %s", config.Version)
	gologger.Info().Msgf("Nuclei Config Directory: %s", config.DefaultConfig.GetConfigDir())
	gologger.Info().Msgf("Nuclei Cache Directory: %s", config.DefaultConfig.GetCacheDir()) // cache dir contains resume files
	gologger.Info().Msgf("PDCP Directory: %s", pdcp.PDCPDir)
	os.Exit(0)
}

// printTemplateVersion prints the nuclei template version and exits.
func printTemplateVersion() {
	cfg := config.DefaultConfig
	gologger.Info().Msgf("Public nuclei-templates version: %s (%s)\n", cfg.TemplateVersion, cfg.TemplatesDirectory)

	if fileutil.FolderExists(cfg.CustomS3TemplatesDirectory) {
		gologger.Info().Msgf("Custom S3 templates location: %s\n", cfg.CustomS3TemplatesDirectory)
	}
	if fileutil.FolderExists(cfg.CustomGitHubTemplatesDirectory) {
		gologger.Info().Msgf("Custom GitHub templates location: %s ", cfg.CustomGitHubTemplatesDirectory)
	}
	if fileutil.FolderExists(cfg.CustomGitLabTemplatesDirectory) {
		gologger.Info().Msgf("Custom GitLab templates location: %s ", cfg.CustomGitLabTemplatesDirectory)
	}
	if fileutil.FolderExists(cfg.CustomAzureTemplatesDirectory) {
		gologger.Info().Msgf("Custom Azure templates location: %s ", cfg.CustomAzureTemplatesDirectory)
	}
	os.Exit(0)
}

func resetCallback() {
	warning := fmt.Sprintf(`
Using '-reset' will delete all nuclei configurations files and all nuclei-templates

Following files will be deleted:
1. All Config + Resumes files at %v
2. All nuclei-templates at %v

Note: Make sure you have backup of your custom nuclei-templates before proceeding

`, config.DefaultConfig.GetConfigDir(), config.DefaultConfig.TemplatesDirectory)
	gologger.Print().Msg(warning)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Are you sure you want to continue? [y/n]: ")
		resp, err := reader.ReadString('\n')
		if err != nil {
			gologger.Fatal().Msgf("could not read response: %s", err)
		}
		resp = strings.TrimSpace(resp)
		if stringsutil.EqualFoldAny(resp, "y", "yes") {
			break
		}
		if stringsutil.EqualFoldAny(resp, "n", "no", "") {
			fmt.Println("Exiting...")
			os.Exit(0)
		}
	}
	err := os.RemoveAll(config.DefaultConfig.GetConfigDir())
	if err != nil {
		gologger.Fatal().Msgf("could not delete config dir: %s", err)
	}
	err = os.RemoveAll(config.DefaultConfig.TemplatesDirectory)
	if err != nil {
		gologger.Fatal().Msgf("could not delete templates dir: %s", err)
	}
	gologger.Info().Msgf("Successfully deleted all nuclei configurations files and nuclei-templates")
	os.Exit(0)
}

func findProfilePathById(profileId, templatesDir string) string {
	var profilePath string
	err := filepath.WalkDir(templatesDir, func(iterItem string, d fs.DirEntry, err error) error {
		ext := filepath.Ext(iterItem)
		isYaml := ext == extensions.YAML || ext == extensions.YML
		if err != nil || d.IsDir() || !isYaml {
			// skip non yaml files
			return nil
		}
		if strings.TrimSuffix(filepath.Base(iterItem), ext) == profileId {
			profilePath = iterItem
			return fmt.Errorf("FOUND")
		}
		return nil
	})
	if err != nil && err.Error() != "FOUND" {
		gologger.Error().Msgf("%s\n", err)
	}
	return profilePath
}

func init() {
	// print stacktrace of errors in debug mode
	if strings.EqualFold(os.Getenv("DEBUG"), "true") {
		errorutil.ShowStackTrace = true
	}
}
