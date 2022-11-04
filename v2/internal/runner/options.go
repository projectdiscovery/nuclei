package runner

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-playground/validator/v10"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

func ConfigureOptions() error {
	isFromFileFunc := func(s string) bool {
		return !isTemplate(s)
	}
	goflags.FileNormalizedStringSliceOptions.IsFromFile = isFromFileFunc
	goflags.FileStringSliceOptions.IsFromFile = isFromFileFunc
	goflags.FileCommaSeparatedStringSliceOptions.IsFromFile = isFromFileFunc
	return nil
}

// ParseOptions parses the command line flags provided by a user
func ParseOptions(options *types.Options) {
	// Check if stdin pipe was given
	options.Stdin = !options.DisableStdin && fileutil.HasStdin()

	// Read the inputs and configure the logging
	configureOutput(options)
	// Show the user the banner
	showBanner()

	if options.TemplatesDirectory != "" && !filepath.IsAbs(options.TemplatesDirectory) {
		cwd, _ := os.Getwd()
		options.TemplatesDirectory = filepath.Join(cwd, options.TemplatesDirectory)
	}
	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", config.Version)
		os.Exit(0)
	}
	if options.TemplatesVersion {
		configuration, err := config.ReadConfiguration()
		if err != nil {
			gologger.Fatal().Msgf("Could not read template configuration: %s\n", err)
		}
		gologger.Info().Msgf("Current nuclei-templates version: %s (%s)\n", configuration.TemplateVersion, configuration.TemplatesDirectory)
		os.Exit(0)
	}
	if options.ShowActions {
		gologger.Info().Msgf("Showing available headless actions: ")
		for action := range engine.ActionStringToAction {
			gologger.Print().Msgf("\t%s", action)
		}
		os.Exit(0)
	}
	if options.StoreResponseDir != DefaultDumpTrafficOutputFolder && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"store-resp\" flag automatically\n")
		options.StoreResponse = true
	}
	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	if err := validateOptions(options); err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	// Load the resolvers if user asked for them
	loadResolvers(options)

	// removes all cli variables containing payloads and add them to the internal struct
	for key, value := range options.Vars.AsMap() {
		if fileutil.FileExists(value.(string)) {
			_ = options.Vars.Del(key)
			options.AddVarPayload(key, value)
		}
	}

	err := protocolinit.Init(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not initialize protocols: %s\n", err)
	}

	if options.UncoverQuery != nil {
		options.Uncover = true
		if len(options.UncoverEngine) == 0 {
			options.UncoverEngine = append(options.UncoverEngine, "shodan")
		}
	}
}

// validateOptions validates the configuration options passed
func validateOptions(options *types.Options) error {
	validate := validator.New()
	if err := validate.Struct(options); err != nil {
		if _, ok := err.(*validator.InvalidValidationError); ok {
			return err
		}
		errs := []string{}
		for _, err := range err.(validator.ValidationErrors) {
			errs = append(errs, err.Namespace()+": "+err.Tag())
		}
		return errors.Wrap(errors.New(strings.Join(errs, ", ")), "validation failed for these fields")
	}
	if options.Verbose && options.Silent {
		return errors.New("both verbose and silent mode specified")
	}

	if options.FollowHostRedirects && options.FollowRedirects {
		return errors.New("both follow host redirects and follow redirects specified")
	}
	if options.ShouldFollowHTTPRedirects() && options.DisableRedirects {
		return errors.New("both follow redirects and disable redirects specified")
	}
	// loading the proxy server list from file or cli and test the connectivity
	if err := loadProxyServers(options); err != nil {
		return err
	}
	if options.Validate {
		validateTemplatePaths(options.TemplatesDirectory, options.Templates, options.Workflows)
	}

	// Verify if any of the client certificate options were set since it requires all three to work properly
	if len(options.ClientCertFile) > 0 || len(options.ClientKeyFile) > 0 || len(options.ClientCAFile) > 0 {
		if len(options.ClientCertFile) == 0 || len(options.ClientKeyFile) == 0 || len(options.ClientCAFile) == 0 {
			return errors.New("if a client certification option is provided, then all three must be provided")
		}
		validateCertificatePaths([]string{options.ClientCertFile, options.ClientKeyFile, options.ClientCAFile})
	}

	return nil
}

// configureOutput configures the output logging levels to be displayed on the screen
func configureOutput(options *types.Options) {
	// If the user desires verbose output, show verbose output
	if options.Verbose || options.Validate {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug || options.DebugRequests || options.DebugResponse {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	// disable standard logger (ref: https://github.com/golang/go/issues/19895)
	log.SetFlags(0)
	log.SetOutput(io.Discard)
}

// loadResolvers loads resolvers from both user provided flag and file
func loadResolvers(options *types.Options) {
	if options.ResolversFile == "" {
		return
	}

	file, err := os.Open(options.ResolversFile)
	if err != nil {
		gologger.Fatal().Msgf("Could not open resolvers file: %s\n", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		part := scanner.Text()
		if part == "" {
			continue
		}
		if strings.Contains(part, ":") {
			options.InternalResolversList = append(options.InternalResolversList, part)
		} else {
			options.InternalResolversList = append(options.InternalResolversList, part+":53")
		}
	}
}

func validateTemplatePaths(templatesDirectory string, templatePaths, workflowPaths []string) {
	allGivenTemplatePaths := append(templatePaths, workflowPaths...)
	for _, templatePath := range allGivenTemplatePaths {
		if templatesDirectory != templatePath && filepath.IsAbs(templatePath) {
			fileInfo, err := os.Stat(templatePath)
			if err == nil && fileInfo.IsDir() {
				relativizedPath, err2 := filepath.Rel(templatesDirectory, templatePath)
				if err2 != nil || (len(relativizedPath) >= 2 && relativizedPath[:2] == "..") {
					gologger.Warning().Msgf("The given path (%s) is outside the default template directory path (%s)! "+
						"Referenced sub-templates with relative paths in workflows will be resolved against the default template directory.", templatePath, templatesDirectory)
					break
				}
			}
		}
	}
}

func validateCertificatePaths(certificatePaths []string) {
	for _, certificatePath := range certificatePaths {
		if _, err := os.Stat(certificatePath); os.IsNotExist(err) {
			// The provided path to the PEM certificate does not exist for the client authentication. As this is
			// required for successful authentication, log and return an error
			gologger.Fatal().Msgf("The given path (%s) to the certificate does not exist!", certificatePath)
			break
		}
	}
}
