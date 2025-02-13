package runner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/go-playground/validator/v10"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/jsonexporter"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/jsonl"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/markdown"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/projectdiscovery/utils/generic"
	logutil "github.com/projectdiscovery/utils/log"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

const (
	// Default directory used to save protocols traffic
	DefaultDumpTrafficOutputFolder = "output"
)

func ConfigureOptions() error {
	// with FileStringSliceOptions, FileNormalizedStringSliceOptions, FileCommaSeparatedStringSliceOptions
	// if file has the extension `.yaml` or `.json` we consider those as strings and not files to be read
	isFromFileFunc := func(s string) bool {
		return !config.IsTemplate(s)
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

	// Read the inputs from env variables that not passed by flag.
	readEnvInputVars(options)

	// Read the inputs and configure the logging
	configureOutput(options)

	// Show the user the banner
	showBanner()

	if options.ShowVarDump {
		vardump.EnableVarDump = true
		vardump.Limit = options.VarDumpLimit
	}
	if options.ShowActions {
		gologger.Info().Msgf("Showing available headless actions: ")
		for action := range engine.ActionStringToAction {
			gologger.Print().Msgf("\t%s", action)
		}
		os.Exit(0)
	}

	defaultProfilesPath := filepath.Join(config.DefaultConfig.GetTemplateDir(), "profiles")
	if options.ListTemplateProfiles {
		gologger.Print().Msgf(
			"\nListing available %v nuclei template profiles for %v",
			config.DefaultConfig.TemplateVersion,
			config.DefaultConfig.TemplatesDirectory,
		)
		templatesRootDir := config.DefaultConfig.GetTemplateDir()
		err := filepath.WalkDir(defaultProfilesPath, func(iterItem string, d fs.DirEntry, err error) error {
			ext := filepath.Ext(iterItem)
			isYaml := ext == extensions.YAML || ext == extensions.YML
			if err != nil || d.IsDir() || !isYaml {
				return nil
			}
			if profileRelPath, err := filepath.Rel(templatesRootDir, iterItem); err == nil {
				gologger.Print().Msgf("%s (%s)\n", profileRelPath, strings.TrimSuffix(filepath.Base(iterItem), ext))
			}
			return nil
		})
		if err != nil {
			gologger.Error().Msgf("%s\n", err)
		}
		os.Exit(0)
	}
	if options.StoreResponseDir != DefaultDumpTrafficOutputFolder && !options.StoreResponse {
		gologger.Debug().Msgf("Store response directory specified, enabling \"store-resp\" flag automatically\n")
		options.StoreResponse = true
	}
	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	if err := ValidateOptions(options); err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	// Load the resolvers if user asked for them
	loadResolvers(options)

	err := protocolinit.Init(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not initialize protocols: %s\n", err)
	}

	// Set GitHub token in env variable. runner.getGHClientWithToken() reads token from env
	if options.GitHubToken != "" && os.Getenv("GITHUB_TOKEN") != options.GitHubToken {
		os.Setenv("GITHUB_TOKEN", options.GitHubToken)
	}

	if options.UncoverQuery != nil {
		options.Uncover = true
		if len(options.UncoverEngine) == 0 {
			options.UncoverEngine = append(options.UncoverEngine, "shodan")
		}
	}

	if options.OfflineHTTP {
		options.DisableHTTPProbe = true
	}
}

// validateOptions validates the configuration options passed
func ValidateOptions(options *types.Options) error {
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

	if (options.HeadlessOptionalArguments != nil || options.ShowBrowser || options.UseInstalledChrome) && !options.Headless {
		return errors.New("headless mode (-headless) is required if -ho, -sb, -sc or -lha are set")
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
		validateTemplatePaths(config.DefaultConfig.TemplatesDirectory, options.Templates, options.Workflows)
	}
	if options.DAST {
		if err := validateDASTOptions(options); err != nil {
			return err
		}
	}

	// Verify if any of the client certificate options were set since it requires all three to work properly
	if options.HasClientCertificates() {
		if generic.EqualsAny("", options.ClientCertFile, options.ClientKeyFile, options.ClientCAFile) {
			return errors.New("if a client certification option is provided, then all three must be provided")
		}
		validateCertificatePaths(options.ClientCertFile, options.ClientKeyFile, options.ClientCAFile)
	}
	// Verify AWS secrets are passed if a S3 template bucket is passed
	if options.AwsBucketName != "" && options.UpdateTemplates && !options.AwsTemplateDisableDownload {
		missing := validateMissingS3Options(options)
		if missing != nil {
			return fmt.Errorf("aws s3 bucket details are missing. Please provide %s", strings.Join(missing, ","))
		}
	}

	// Verify Azure connection configuration is passed if the Azure template bucket is passed
	if options.AzureContainerName != "" && options.UpdateTemplates && !options.AzureTemplateDisableDownload {
		missing := validateMissingAzureOptions(options)
		if missing != nil {
			return fmt.Errorf("azure connection details are missing. Please provide %s", strings.Join(missing, ","))
		}
	}

	// Verify that all GitLab options are provided if the GitLab server or token is provided
	if len(options.GitLabTemplateRepositoryIDs) != 0 && options.UpdateTemplates && !options.GitLabTemplateDisableDownload {
		missing := validateMissingGitLabOptions(options)
		if missing != nil {
			return fmt.Errorf("gitlab server details are missing. Please provide %s", strings.Join(missing, ","))
		}
	}

	// verify that a valid ip version type was selected (4, 6)
	if len(options.IPVersion) == 0 {
		// add ipv4 as default
		options.IPVersion = append(options.IPVersion, "4")
	}
	var useIPV4, useIPV6 bool
	for _, ipv := range options.IPVersion {
		switch ipv {
		case "4":
			useIPV4 = true
		case "6":
			useIPV6 = true
		default:
			return fmt.Errorf("unsupported ip version: %s", ipv)
		}
	}
	if !useIPV4 && !useIPV6 {
		return errors.New("ipv4 and/or ipv6 must be selected")
	}
	return nil
}

func validateMissingS3Options(options *types.Options) []string {
	var missing []string
	if options.AwsBucketName == "" {
		missing = append(missing, "AWS_TEMPLATE_BUCKET")
	}
	if options.AwsAccessKey == "" {
		missing = append(missing, "AWS_ACCESS_KEY")
	}
	if options.AwsSecretKey == "" {
		missing = append(missing, "AWS_SECRET_KEY")
	}
	if options.AwsRegion == "" {
		missing = append(missing, "AWS_REGION")
	}
	return missing
}

func validateMissingAzureOptions(options *types.Options) []string {
	var missing []string
	if options.AzureTenantID == "" {
		missing = append(missing, "AZURE_TENANT_ID")
	}
	if options.AzureClientID == "" {
		missing = append(missing, "AZURE_CLIENT_ID")
	}
	if options.AzureClientSecret == "" {
		missing = append(missing, "AZURE_CLIENT_SECRET")
	}
	if options.AzureServiceURL == "" {
		missing = append(missing, "AZURE_SERVICE_URL")
	}
	if options.AzureContainerName == "" {
		missing = append(missing, "AZURE_CONTAINER_NAME")
	}
	return missing
}

func validateMissingGitLabOptions(options *types.Options) []string {
	var missing []string
	if options.GitLabToken == "" {
		missing = append(missing, "GITLAB_TOKEN")
	}
	if len(options.GitLabTemplateRepositoryIDs) == 0 {
		missing = append(missing, "GITLAB_REPOSITORY_IDS")
	}

	return missing
}

func validateDASTOptions(options *types.Options) error {
	// Ensure the DAST server token meets minimum length requirement
	if len(options.DASTServerToken) > 0 && len(options.DASTServerToken) < 16 {
		return fmt.Errorf("DAST server token must be at least 16 characters long")
	}
	return nil
}

func createReportingOptions(options *types.Options) (*reporting.Options, error) {
	var reportingOptions = &reporting.Options{}
	if options.ReportingConfig != "" {
		file, err := os.Open(options.ReportingConfig)
		if err != nil {
			return nil, errors.Wrap(err, "could not open reporting config file")
		}
		defer file.Close()

		if err := yaml.DecodeAndValidate(file, reportingOptions); err != nil {
			return nil, errors.Wrap(err, "could not parse reporting config file")
		}
		Walk(reportingOptions, expandEndVars)
	}
	if options.MarkdownExportDirectory != "" {
		reportingOptions.MarkdownExporter = &markdown.Options{
			Directory: options.MarkdownExportDirectory,
			OmitRaw:   options.OmitRawRequests,
			SortMode:  options.MarkdownExportSortMode,
		}
	}
	if options.SarifExport != "" {
		reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
	}
	if options.JSONExport != "" {
		reportingOptions.JSONExporter = &jsonexporter.Options{
			File:    options.JSONExport,
			OmitRaw: options.OmitRawRequests,
		}
	}
	// Combine options.
	if options.JSONLExport != "" {
		// Combine the CLI options with the config file options with the CLI options taking precedence
		if reportingOptions.JSONLExporter != nil {
			reportingOptions.JSONLExporter.File = options.JSONLExport
			reportingOptions.JSONLExporter.OmitRaw = options.OmitRawRequests
		} else {
			reportingOptions.JSONLExporter = &jsonl.Options{
				File:    options.JSONLExport,
				OmitRaw: options.OmitRawRequests,
			}
		}
	}

	reportingOptions.OmitRaw = options.OmitRawRequests
	return reportingOptions, nil
}

// configureOutput configures the output logging levels to be displayed on the screen
func configureOutput(options *types.Options) {
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	// If the user desires verbose output, show verbose output
	if options.Debug || options.DebugRequests || options.DebugResponse {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	// Debug takes precedence before verbose
	// because debug is a lower logging level.
	if options.Verbose || options.Validate {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	// disable standard logger (ref: https://github.com/golang/go/issues/19895)
	logutil.DisableDefaultLogger()
}

// loadResolvers loads resolvers from both user-provided flags and file
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

func validateCertificatePaths(certificatePaths ...string) {
	for _, certificatePath := range certificatePaths {
		if !fileutil.FileExists(certificatePath) {
			// The provided path to the PEM certificate does not exist for the client authentication. As this is
			// required for successful authentication, log and return an error
			gologger.Fatal().Msgf("The given path (%s) to the certificate does not exist!", certificatePath)
			break
		}
	}
}

// Read the input from env and set options
func readEnvInputVars(options *types.Options) {
	options.GitHubToken = os.Getenv("GITHUB_TOKEN")
	repolist := os.Getenv("GITHUB_TEMPLATE_REPO")
	if repolist != "" {
		options.GitHubTemplateRepo = append(options.GitHubTemplateRepo, stringsutil.SplitAny(repolist, ",")...)
	}

	// GitLab options for downloading templates from a repository
	options.GitLabServerURL = os.Getenv("GITLAB_SERVER_URL")
	if options.GitLabServerURL == "" {
		options.GitLabServerURL = "https://gitlab.com"
	}
	options.GitLabToken = os.Getenv("GITLAB_TOKEN")
	repolist = os.Getenv("GITLAB_REPOSITORY_IDS")
	// Convert the comma separated list of repository IDs to a list of integers
	if repolist != "" {
		for _, repoID := range stringsutil.SplitAny(repolist, ",") {
			// Attempt to convert the repo ID to an integer
			repoIDInt, err := strconv.Atoi(repoID)
			if err != nil {
				gologger.Warning().Msgf("Invalid GitLab template repository ID: %s", repoID)
				continue
			}

			// Add the int repository ID to the list
			options.GitLabTemplateRepositoryIDs = append(options.GitLabTemplateRepositoryIDs, repoIDInt)
		}
	}

	// AWS options for downloading templates from an S3 bucket
	options.AwsAccessKey = os.Getenv("AWS_ACCESS_KEY")
	options.AwsSecretKey = os.Getenv("AWS_SECRET_KEY")
	options.AwsBucketName = os.Getenv("AWS_TEMPLATE_BUCKET")
	options.AwsRegion = os.Getenv("AWS_REGION")

	// Azure options for downloading templates from an Azure Blob Storage container
	options.AzureContainerName = os.Getenv("AZURE_CONTAINER_NAME")
	options.AzureTenantID = os.Getenv("AZURE_TENANT_ID")
	options.AzureClientID = os.Getenv("AZURE_CLIENT_ID")
	options.AzureClientSecret = os.Getenv("AZURE_CLIENT_SECRET")
	options.AzureServiceURL = os.Getenv("AZURE_SERVICE_URL")

	// Custom public keys for template verification
	options.CodeTemplateSignaturePublicKey = os.Getenv("NUCLEI_SIGNATURE_PUBLIC_KEY")
	options.CodeTemplateSignatureAlgorithm = os.Getenv("NUCLEI_SIGNATURE_ALGORITHM")

	// General options to disable the template download locations from being used.
	// This will override the default behavior of downloading templates from the default locations as well as the
	// custom locations.
	// The primary use-case is when the user wants to use custom templates only and does not want to download any
	// templates from the default locations or is unable to connect to the public internet.
	options.PublicTemplateDisableDownload = getBoolEnvValue("DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD")
	options.GitHubTemplateDisableDownload = getBoolEnvValue("DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD")
	options.GitLabTemplateDisableDownload = getBoolEnvValue("DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD")
	options.AwsTemplateDisableDownload = getBoolEnvValue("DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD")
	options.AzureTemplateDisableDownload = getBoolEnvValue("DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD")

	// Options to modify the behavior of exporters
	options.MarkdownExportSortMode = strings.ToLower(os.Getenv("MARKDOWN_EXPORT_SORT_MODE"))
	// If the user has not specified a valid sort mode, use the default
	if options.MarkdownExportSortMode != "template" && options.MarkdownExportSortMode != "severity" && options.MarkdownExportSortMode != "host" {
		options.MarkdownExportSortMode = ""
	}
}

func getBoolEnvValue(key string) bool {
	value := os.Getenv(key)
	return strings.EqualFold(value, "true")
}
