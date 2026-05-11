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

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/env"
	_ "github.com/projectdiscovery/utils/pprof"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/rs/xid"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/monitor"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
)

var (
	cfgFile                string
	templateProfile        string
	memProfile             string // optional profile file path
	options                = &types.Options{}
	inlineSecretsTempFiles []string
)

func main() {
	options.Logger = gologger.DefaultLogger

	defer func() {
		for _, f := range inlineSecretsTempFiles {
			_ = os.Remove(f)
		}
	}()

	// enables CLI specific configs mostly interactive behavior
	config.CurrentAppMode = config.AppModeCLI

	if err := runner.ConfigureOptions(); err != nil {
		options.Logger.Fatal().Msgf("Could not initialize options: %s\n", err)
	}
	_ = readConfig()

	if options.ListDslSignatures {
		options.Logger.Info().Msgf("The available custom DSL functions are:")
		fmt.Println(dsl.GetPrintableDslFunctionSignatures(options.NoColor))
		return
	}

	// sign the templates if requested - only glob syntax is supported
	if options.SignTemplates {
		// use parsed options when initializing signer instead of default options
		templates.UseOptionsForSigner(options)
		tsigner, err := signer.NewTemplateSigner(nil, nil) // will read from env , config or generate new keys
		if err != nil {
			options.Logger.Fatal().Msgf("couldn't initialize signer crypto engine: %s\n", err)
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
						options.Logger.Error().Msgf("could not sign '%s': %s\n", iterItem, err)
					}
				} else {
					successCounter++
				}

				return nil
			})
			if err != nil {
				options.Logger.Error().Msgf("%s\n", err)
			}
		}
		options.Logger.Info().Msgf("All templates signatures were elaborated success=%d failed=%d\n", successCounter, errorCounter)
		return
	}

	// Profiling & tracing related code
	if memProfile != "" {
		memProfile = strings.TrimSuffix(memProfile, filepath.Ext(memProfile))

		createProfileFile := func(ext, profileType string) *os.File {
			f, err := os.Create(memProfile + ext)
			if err != nil {
				options.Logger.Fatal().Msgf("profile: could not create %s profile %q file: %v", profileType, f.Name(), err)
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
			options.Logger.Fatal().Msgf("profile: could not start trace: %v", err)
		}

		// Start CPU profiling
		if err := pprof.StartCPUProfile(cpuProfileFile); err != nil {
			options.Logger.Fatal().Msgf("profile: could not start CPU profile: %v", err)
		}

		defer func() {
			// Start heap memory snapshot
			if err := pprof.WriteHeapProfile(memProfileFile); err != nil {
				options.Logger.Fatal().Msgf("profile: could not write memory profile: %v", err)
			}

			pprof.StopCPUProfile()
			_ = memProfileFile.Close()
			_ = traceFile.Close()
			trace.Stop()

			runtime.MemProfileRate = oldMemProfileRate

			options.Logger.Info().Msgf("CPU profile saved at %q", cpuProfileFile.Name())
			options.Logger.Info().Msgf("Memory usage snapshot saved at %q", memProfileFile.Name())
			options.Logger.Info().Msgf("Traced at %q", traceFile.Name())
		}()
	}

	options.ExecutionId = xid.New().String()

	runner.ParseOptions(options)

	if options.ScanUploadFile != "" {
		if err := runner.UploadResultsToCloud(options); err != nil {
			options.Logger.Fatal().Msgf("could not upload scan results to cloud dashboard: %s\n", err)
		}
		return
	}

	nucleiRunner, err := runner.New(options)
	if err != nil {
		options.Logger.Fatal().Msgf("Could not create runner: %s\n", err)
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
				options.Logger.Info().Msgf("Uploading scan results to cloud...")
			}
			nucleiRunner.Close()
			options.Logger.Info().Msgf("Creating resume file: %s\n", resumeFileName)
			err := nucleiRunner.SaveResumeConfig(resumeFileName)
			if err != nil {
				return errkit.Wrap(err, "couldn't create crash resume file")
			}
			return nil
		})
	}

	// Setup filename for graceful exits
	resumeFileName := types.DefaultResumeFilePath()
	if options.Resume != "" {
		resumeFileName = options.Resume
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		options.Logger.Info().Msgf("CTRL+C pressed: Exiting\n")
		if options.DASTServer {
			nucleiRunner.Close()
			os.Exit(1)
		}

		options.Logger.Info().Msgf("Attempting graceful shutdown...")
		if options.EnableCloudUpload {
			options.Logger.Info().Msgf("Uploading scan results to cloud...")
		}
		nucleiRunner.Close()
		if options.ShouldSaveResume() {
			options.Logger.Info().Msgf("Creating resume file: %s\n", resumeFileName)
			err := nucleiRunner.SaveResumeConfig(resumeFileName)
			if err != nil {
				options.Logger.Error().Msgf("Couldn't create resume file: %s\n", err)
			}
		}
		for _, f := range inlineSecretsTempFiles {
			_ = os.Remove(f)
		}
		os.Exit(1)
	}()

	if err := nucleiRunner.RunEnumeration(); err != nil {
		if options.Validate {
			options.Logger.Fatal().Msgf("Could not validate templates: %s\n", err)
		} else {
			options.Logger.Fatal().Msgf("Could not run nuclei: %s\n", err)
		}
	}
	nucleiRunner.Close()
	// on successful execution remove the resume file in case it exists
	if fileutil.FileExists(resumeFileName) {
		_ = os.Remove(resumeFileName)
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

	runner.BindOptionFlags(flagSet, options)

	flagSet.CreateGroup("configs-cli", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the nuclei configuration file"),
		flagSet.StringVarP(&templateProfile, "profile", "tp", "", "template profile config file to run"),
		flagSet.BoolVarP(&options.ListTemplateProfiles, "profile-list", "tpl", false, "list community template profiles"),
		flagSet.CallbackVar(resetCallback, "reset", "reset removes all nuclei configuration and data files (including nuclei-templates)"),
	)

	flagSet.CreateGroup("fuzzing-cli", "Fuzzing",
		flagSet.BoolVar(&fuzzFlag, "fuzz", false, "enable loading fuzzing templates (Deprecated: use -dast instead)"),
	)

	flagSet.CreateGroup("debug-cli", "Debug",
		flagSet.CallbackVar(printVersion, "version", "show nuclei version"),
		flagSet.StringVar(&memProfile, "profile-mem", "", "generate memory (heap) profile & trace files"),
		flagSet.CallbackVarP(printTemplateVersion, "templates-version", "tv", "shows the version of the installed nuclei-templates"),
	)

	flagSet.CreateGroup("update-cli", "Update",
		flagSet.BoolVarP(&updateNucleiBinary, "update", "up", false, "update nuclei engine to the latest released version"),
		flagSet.CallbackVarP(disableUpdatesCallback, "disable-update-check", "duc", "disable automatic nuclei/templates update check"),
	)

	flagSet.CreateGroup("cloud-cli", "Cloud",
		flagSet.DynamicVar(&pdcpauth, "auth", "true", "configure projectdiscovery cloud (pdcp) api key"),
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
			options.Logger.Fatal().Msg("To utilize the `-ai` flag, please configure your API key with the `-auth` flag or set the `PDCP_API_KEY` environment variable")
		}
	}

	options.Logger.SetTimestamp(options.Timestamp, levels.LevelDebug)

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
			options.Logger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			options.Logger.Fatal().Msgf("Could not read config: %s\n", err)
		}

		if !options.Vars.IsEmpty() {
			// Maybe we should add vars to the config file as well even if they are set via flags?
			file, err := os.Open(cfgFile)
			if err != nil {
				gologger.Fatal().Msgf("Could not open config file: %s\n", err)
			}
			defer func() {
				_ = file.Close()
			}()
			data := make(map[string]interface{})
			err = yaml.NewDecoder(file).Decode(&data)
			if err != nil {
				gologger.Fatal().Msgf("Could not decode config file: %s\n", err)
			}

			variables := data["var"]
			if variables != nil {
				if varSlice, ok := variables.([]interface{}); ok {
					for _, value := range varSlice {
						if strVal, ok := value.(string); ok {
							err = options.Vars.Set(strVal)
							if err != nil {
								gologger.Warning().Msgf("Could not set variable from config file: %s\n", err)
							}
						} else {
							gologger.Warning().Msgf("Skipping non-string variable in config: %#v", value)
						}
					}
				} else {
					gologger.Warning().Msgf("No 'var' section found in config file: %s", cfgFile)
				}
			}

		}
	}

	templatesDir := options.NewTemplatesDirectory
	if templatesDir == "" {
		templatesDir = os.Getenv(config.NucleiTemplatesDirEnv)
	}
	if templatesDir != "" {
		config.DefaultConfig.SetTemplatesDir(templatesDir)
	}

	defaultProfilesPath := filepath.Join(config.DefaultConfig.GetTemplateDir(), "profiles")
	if templateProfile != "" {
		if filepath.Ext(templateProfile) == "" {
			if tp := findProfilePathById(templateProfile, defaultProfilesPath); tp != "" {
				templateProfile = tp
			} else {
				options.Logger.Fatal().Msgf("'%s' is not a profile-id or profile path", templateProfile)
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
			options.Logger.Fatal().Msgf("given template profile file '%s' does not exist", templateProfile)
		}
		if err := flagSet.MergeConfigFile(templateProfile); err != nil {
			options.Logger.Fatal().Msgf("Could not read template profile: %s\n", err)
		}

		// Process inline target list from profile.
		// Supports both the dedicated targets-inline key and multiline
		// content in the list key (which normally holds a file path).
		if options.InlineTargetsList != "" {
			inlineTargets := strings.Split(strings.TrimSpace(options.InlineTargetsList), "\n")
			for _, target := range inlineTargets {
				target = strings.TrimSpace(target)
				if target != "" && !strings.HasPrefix(target, "#") {
					options.Targets = append(options.Targets, target)
				}
			}
		}
		if strings.Contains(options.TargetsFilePath, "\n") {
			// list key has multiline content, treat as inline targets
			inlineTargets := strings.Split(strings.TrimSpace(options.TargetsFilePath), "\n")
			for _, target := range inlineTargets {
				target = strings.TrimSpace(target)
				if target != "" && !strings.HasPrefix(target, "#") {
					options.Targets = append(options.Targets, target)
				}
			}
			options.TargetsFilePath = ""
		}

		// Process inline secrets from profile YAML
		tempSecretsFile, err := processInlineSecretsFromProfile(templateProfile, options)
		if err != nil {
			options.Logger.Fatal().Msgf("Could not process inline secrets: %s\n", err)
		}
		if tempSecretsFile != "" {
			inlineSecretsTempFiles = append(inlineSecretsTempFiles, tempSecretsFile)
		}
	}

	if len(options.SecretsFile) > 0 {
		for _, secretFile := range options.SecretsFile {
			if !fileutil.FileExists(secretFile) {
				options.Logger.Fatal().Msgf("given secrets file '%s' does not exist", secretFile)
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
		options.Logger.Warning().Msgf("Could not read config file: %s\n", err)
		return
	}
	cfgFile := config.DefaultConfig.GetFlagsConfigFilePath()
	if !fileutil.FileExists(cfgFile) {
		if !fileutil.FileExists(defaultCfgFile) {
			// if default config does not exist, warn and exit
			options.Logger.Warning().Msgf("missing default config file : %s", defaultCfgFile)
			return
		}
		// if does not exist copy it from the default config
		if err = fileutil.CopyFile(defaultCfgFile, cfgFile); err != nil {
			options.Logger.Warning().Msgf("Could not copy config file: %s\n", err)
		}
		return
	}
	// if config file exists, merge it with the default config
	if err = flagset.MergeConfigFile(cfgFile); err != nil {
		options.Logger.Warning().Msgf("failed to merge configfile with flags got: %s\n", err)
	}
}

// disableUpdatesCallback disables the update check.
func disableUpdatesCallback() {
	config.DefaultConfig.DisableUpdateCheck()
}

// printVersion prints the nuclei version and exits.
func printVersion() {
	options.Logger.Info().Msgf("Nuclei Engine Version: %s", config.Version)
	options.Logger.Info().Msgf("Nuclei Config Directory: %s", config.DefaultConfig.GetConfigDir())
	options.Logger.Info().Msgf("Nuclei Cache Directory: %s", config.DefaultConfig.GetCacheDir()) // cache dir contains resume files
	options.Logger.Info().Msgf("PDCP Directory: %s", pdcp.PDCPDir)
	os.Exit(0)
}

// printTemplateVersion prints the nuclei template version and exits.
func printTemplateVersion() {
	cfg := config.DefaultConfig
	options.Logger.Info().Msgf("Public nuclei-templates version: %s (%s)\n", cfg.TemplateVersion, cfg.TemplatesDirectory)

	if fileutil.FolderExists(cfg.CustomS3TemplatesDirectory) {
		options.Logger.Info().Msgf("Custom S3 templates location: %s\n", cfg.CustomS3TemplatesDirectory)
	}
	if fileutil.FolderExists(cfg.CustomGitHubTemplatesDirectory) {
		options.Logger.Info().Msgf("Custom GitHub templates location: %s ", cfg.CustomGitHubTemplatesDirectory)
	}
	if fileutil.FolderExists(cfg.CustomGitLabTemplatesDirectory) {
		options.Logger.Info().Msgf("Custom GitLab templates location: %s ", cfg.CustomGitLabTemplatesDirectory)
	}
	if fileutil.FolderExists(cfg.CustomAzureTemplatesDirectory) {
		options.Logger.Info().Msgf("Custom Azure templates location: %s ", cfg.CustomAzureTemplatesDirectory)
	}
	os.Exit(0)
}

func resetCallback() {
	warning := fmt.Sprintf(`
Using '-reset' will delete all nuclei configurations files and all nuclei-templates

Following files will be deleted:
1. All config files at %v
2. All cache files (including resume state) at %v
3. All nuclei-templates at %v

Note: Make sure you have backup of your custom nuclei-templates before proceeding

`, config.DefaultConfig.GetConfigDir(), config.DefaultConfig.GetCacheDir(), config.DefaultConfig.TemplatesDirectory)
	options.Logger.Print().Msg(warning)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Are you sure you want to continue? [y/n]: ")
		resp, err := reader.ReadString('\n')
		if err != nil {
			options.Logger.Fatal().Msgf("could not read response: %s", err)
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
		options.Logger.Fatal().Msgf("could not delete config dir: %s", err)
	}
	err = os.RemoveAll(config.DefaultConfig.GetCacheDir())
	if err != nil {
		options.Logger.Fatal().Msgf("could not delete cache dir: %s", err)
	}
	err = os.RemoveAll(config.DefaultConfig.TemplatesDirectory)
	if err != nil {
		options.Logger.Fatal().Msgf("could not delete templates dir: %s", err)
	}
	options.Logger.Info().Msgf("Successfully deleted all nuclei configurations files and nuclei-templates")
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
		options.Logger.Error().Msgf("%s\n", err)
	}
	return profilePath
}

// profileSecrets is a helper struct to extract secrets section from a template profile YAML
type profileSecrets struct {
	Secrets interface{} `yaml:"secrets"`
}

// processInlineSecretsFromProfile parses the profile YAML file for inline secrets
// and creates a temporary secrets file compatible with nuclei's auth provider.
// Returns the path to the temp file or empty string if no secrets found.
func processInlineSecretsFromProfile(profilePath string, options *types.Options) (string, error) {
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("could not read profile file: %w", err)
	}

	var profile profileSecrets
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return "", fmt.Errorf("could not parse profile YAML: %w", err)
	}

	if profile.Secrets == nil {
		return "", nil
	}

	secretsData, err := yaml.Marshal(profile.Secrets)
	if err != nil {
		return "", fmt.Errorf("could not marshal inline secrets: %w", err)
	}

	tempDir := filepath.Join(os.TempDir(), "nuclei-secrets")
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return "", fmt.Errorf("could not create temp directory: %w", err)
	}

	tempFile, err := os.CreateTemp(tempDir, "inline-secrets-*.yaml")
	if err != nil {
		return "", fmt.Errorf("could not create temp secrets file: %w", err)
	}
	defer func() {
		_ = tempFile.Close()
	}()

	if _, err := tempFile.Write(secretsData); err != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempFile.Name())
		return "", fmt.Errorf("could not write to temp secrets file: %w", err)
	}

	options.SecretsFile = append(options.SecretsFile, tempFile.Name())
	return tempFile.Name(), nil
}
