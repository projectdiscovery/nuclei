package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	errorutil "github.com/projectdiscovery/utils/errors"
	"gopkg.in/yaml.v3"
)

const (
	yamlIndentSpaces = 2
	// templateman api base url
	tmBaseUrlDefault = "https://tm.nuclei.sh"
)

var tmBaseUrl string

func init() {
	tmBaseUrl = os.Getenv("TEMPLATEMAN_SERVER")
	if tmBaseUrl == "" {
		tmBaseUrl = tmBaseUrlDefault
	}
}

// allTagsRegex is a list of all tags in nuclei templates except id, info, and -
var allTagsRegex []*regexp.Regexp
var defaultOpts = types.DefaultOptions()

func init() {
	var tm templates.Template
	t := reflect.TypeOf(tm)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("yaml")
		if strings.Contains(tag, ",") {
			tag = strings.Split(tag, ",")[0]
		}
		// ignore these tags
		if tag == "id" || tag == "info" || tag == "" || tag == "-" {
			continue
		}
		re := regexp.MustCompile(tag + `:\s*\n`)
		if t.Field(i).Type.Kind() == reflect.Bool {
			re = regexp.MustCompile(tag + `:\s*(true|false)\s*\n`)
		}
		allTagsRegex = append(allTagsRegex, re)
	}

	defaultOpts := types.DefaultOptions()
	// need to set headless to true for headless templates
	defaultOpts.Headless = true
	if err := protocolstate.Init(defaultOpts); err != nil {
		gologger.Fatal().Msgf("Could not initialize protocol state: %s\n", err)
	}
	if err := protocolinit.Init(defaultOpts); err != nil {
		gologger.Fatal().Msgf("Could not initialize protocol state: %s\n", err)
	}
}

type options struct {
	input        string
	errorLogFile string
	lint         bool
	validate     bool
	format       bool
	enhance      bool
	maxRequest   bool
	debug        bool
}

func main() {
	opts := options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`TemplateMan CLI is basic utility built on the TemplateMan API to standardize nuclei templates.`)

	flagSet.CreateGroup("Input", "input",
		flagSet.StringVarP(&opts.input, "input", "i", "", "Templates to annotate"),
	)

	flagSet.CreateGroup("Config", "config",
		flagSet.BoolVarP(&opts.lint, "lint", "l", false, "lint given nuclei template"),
		flagSet.BoolVarP(&opts.validate, "validate", "v", false, "validate given nuclei template"),
		flagSet.BoolVarP(&opts.format, "format", "f", false, "format given nuclei template"),
		flagSet.BoolVarP(&opts.enhance, "enhance", "e", false, "enhance given nuclei template"),
		flagSet.BoolVarP(&opts.maxRequest, "max-request", "mr", false, "add / update max request counter"),
		flagSet.StringVarP(&opts.errorLogFile, "error-log", "el", "", "file to write failed template update"),
		flagSet.BoolVarP(&opts.debug, "debug", "d", false, "show debug message"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("Error parsing flags: %s\n", err)
	}

	if opts.input == "" {
		gologger.Fatal().Msg("input template path/directory is required")
	}
	if strings.HasPrefix(opts.input, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Failed to read UserHomeDir: %v, provide absolute template path/directory\n", err)
		}
		opts.input = filepath.Join(home, (opts.input)[2:])
	}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	if opts.debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if err := process(opts); err != nil {
		gologger.Error().Msgf("could not process: %s\n", err)
	}
}

func process(opts options) error {
	tempDir, err := os.MkdirTemp("", "nuclei-nvd-%s")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	var errFile *os.File
	if opts.errorLogFile != "" {
		errFile, err = os.OpenFile(opts.errorLogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			gologger.Fatal().Msgf("could not open error log file: %s\n", err)
		}
		defer errFile.Close()
	}

	templateCatalog := disk.NewCatalog(filepath.Dir(opts.input))
	paths, err := templateCatalog.GetTemplatePath(opts.input)
	if err != nil {
		return err
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dataString := string(data)

		if opts.maxRequest {
			var updated bool // if max-requests is updated
			dataString, updated, err = parseAndAddMaxRequests(templateCatalog, path, dataString)
			if err != nil {
				gologger.Info().Label("max-request").Msgf(logErrMsg(path, err, opts.debug, errFile))
			} else {
				if updated {
					gologger.Info().Label("max-request").Msgf("✅ updated template: %s\n", path)
				}
				// do not print if max-requests is not updated
			}
		}

		if opts.lint {
			lint, err := lintTemplate(dataString)
			if err != nil {
				gologger.Info().Label("lint").Msg(logErrMsg(path, err, opts.debug, errFile))
			}
			if lint {
				gologger.Info().Label("lint").Msgf("✅ lint template: %s\n", path)
			}
		}

		if opts.validate {
			validate, err := validateTemplate(dataString)
			if err != nil {
				gologger.Info().Label("validate").Msg(logErrMsg(path, err, opts.debug, errFile))
			}
			if validate {
				gologger.Info().Label("validate").Msgf("✅ validated template: %s\n", path)
			}
		}

		if opts.format {
			formatedTemplateData, isFormated, err := formatTemplate(dataString)
			if err != nil {
				gologger.Info().Label("format").Msg(logErrMsg(path, err, opts.debug, errFile))
			} else {
				if isFormated {
					_ = os.WriteFile(path, []byte(formatedTemplateData), 0644)
					dataString = formatedTemplateData
					gologger.Info().Label("format").Msgf("✅ formated template: %s\n", path)
				}
			}
		}

		if opts.enhance {
			enhancedTemplateData, isEnhanced, err := enhanceTemplate(dataString)
			if err != nil {
				gologger.Info().Label("enhance").Msg(logErrMsg(path, err, opts.debug, errFile))
				continue
			} else {
				if isEnhanced {
					_ = os.WriteFile(path, []byte(enhancedTemplateData), 0644)
					gologger.Info().Label("enhance").Msgf("✅ updated template: %s\n", path)
				}
			}
		}
	}
	return nil
}

func logErrMsg(path string, err error, debug bool, errFile *os.File) string {
	msg := fmt.Sprintf("❌ template: %s\n", path)
	if debug {
		msg = fmt.Sprintf("❌ template: %s err: %s\n", path, err)
	}
	if errFile != nil {
		_, _ = errFile.WriteString(fmt.Sprintf("❌ template: %s err: %s\n", path, err))
	}
	return msg
}

// enhanceTemplateData enhances template data using templateman
// ref: https://github.com/projectdiscovery/templateman/blob/main/templateman-rest-api/README.md#enhance-api
func enhanceTemplate(data string) (string, bool, error) {
	resp, err := retryablehttp.DefaultClient().Post(fmt.Sprintf("%s/enhance", tmBaseUrl), "application/x-yaml", strings.NewReader(data))
	if err != nil {
		return data, false, err
	}
	if resp.StatusCode != 200 {
		return data, false, errorutil.New("unexpected status code: %v", resp.Status)
	}
	var templateResp TemplateResp
	if err := json.NewDecoder(resp.Body).Decode(&templateResp); err != nil {
		return data, false, err
	}
	if strings.TrimSpace(templateResp.Enhanced) != "" {
		return templateResp.Enhanced, templateResp.Enhance, nil
	}
	if templateResp.ValidateErrorCount > 0 {
		if len(templateResp.ValidateError) > 0 {
			return data, false, errorutil.NewWithTag("validate", templateResp.ValidateError[0].Message+": at line %v", templateResp.ValidateError[0].Mark.Line)
		}
		return data, false, errorutil.New("validation failed").WithTag("validate")
	}
	if templateResp.Error.Name != "" {
		return data, false, errorutil.New(templateResp.Error.Name)
	}
	if strings.TrimSpace(templateResp.Enhanced) == "" && !templateResp.Lint {
		if templateResp.LintError.Reason != "" {
			return data, false, errorutil.NewWithTag("lint", templateResp.LintError.Reason+" : at line %v", templateResp.LintError.Mark.Line)
		}
		return data, false, errorutil.NewWithTag("lint", "at line: %v", templateResp.LintError.Mark.Line)
	}
	return data, false, errorutil.New("template enhance failed")
}

// formatTemplateData formats template data using templateman format api
func formatTemplate(data string) (string, bool, error) {
	resp, err := retryablehttp.DefaultClient().Post(fmt.Sprintf("%s/format", tmBaseUrl), "application/x-yaml", strings.NewReader(data))
	if err != nil {
		return data, false, err
	}
	if resp.StatusCode != 200 {
		return data, false, errorutil.New("unexpected status code: %v", resp.Status)
	}
	var templateResp TemplateResp
	if err := json.NewDecoder(resp.Body).Decode(&templateResp); err != nil {
		return data, false, err
	}
	if strings.TrimSpace(templateResp.Updated) != "" {
		return templateResp.Updated, templateResp.Format, nil
	}
	if templateResp.ValidateErrorCount > 0 {
		if len(templateResp.ValidateError) > 0 {
			return data, false, errorutil.NewWithTag("validate", templateResp.ValidateError[0].Message+": at line %v", templateResp.ValidateError[0].Mark.Line)
		}
		return data, false, errorutil.New("validation failed").WithTag("validate")
	}
	if templateResp.Error.Name != "" {
		return data, false, errorutil.New(templateResp.Error.Name)
	}
	if strings.TrimSpace(templateResp.Updated) == "" && !templateResp.Lint {
		if templateResp.LintError.Reason != "" {
			return data, false, errorutil.NewWithTag("lint", templateResp.LintError.Reason+" : at line %v", templateResp.LintError.Mark.Line)
		}
		return data, false, errorutil.NewWithTag("lint", "at line: %v", templateResp.LintError.Mark.Line)
	}
	return data, false, errorutil.New("template format failed")
}

// lintTemplateData lints template data using templateman lint api
func lintTemplate(data string) (bool, error) {
	resp, err := retryablehttp.DefaultClient().Post(fmt.Sprintf("%s/lint", tmBaseUrl), "application/x-yaml", strings.NewReader(data))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		return false, errorutil.New("unexpected status code: %v", resp.Status)
	}
	var lintResp TemplateLintResp
	if err := json.NewDecoder(resp.Body).Decode(&lintResp); err != nil {
		return false, err
	}
	if lintResp.Lint {
		return true, nil
	}
	if lintResp.LintError.Reason != "" {
		return false, errorutil.NewWithTag("lint", lintResp.LintError.Reason+" : at line %v", lintResp.LintError.Mark.Line)
	}
	return false, errorutil.NewWithTag("lint", "at line: %v", lintResp.LintError.Mark.Line)
}

// validateTemplate validates template data using templateman validate api
func validateTemplate(data string) (bool, error) {
	resp, err := retryablehttp.DefaultClient().Post(fmt.Sprintf("%s/validate", tmBaseUrl), "application/x-yaml", strings.NewReader(data))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		return false, errorutil.New("unexpected status code: %v", resp.Status)
	}
	var validateResp TemplateResp
	if err := json.NewDecoder(resp.Body).Decode(&validateResp); err != nil {
		return false, err
	}
	if validateResp.Validate {
		return true, nil
	}
	if validateResp.ValidateErrorCount > 0 {
		if len(validateResp.ValidateError) > 0 {
			return false, errorutil.NewWithTag("validate", validateResp.ValidateError[0].Message+": at line %v", validateResp.ValidateError[0].Mark.Line)
		}
		return false, errorutil.New("validation failed").WithTag("validate")
	}
	if validateResp.Error.Name != "" {
		return false, errorutil.New(validateResp.Error.Name)
	}
	return false, errorutil.New("template validation failed")
}

// parseAndAddMaxRequests parses and adds max requests to templates
func parseAndAddMaxRequests(catalog catalog.Catalog, path, data string) (string, bool, error) {
	template, err := parseTemplate(catalog, path)
	if err != nil {
		return data, false, err
	}
	if template.TotalRequests < 1 {
		return data, false, nil
	}
	// Marshal the updated info block back to YAML.
	infoBlockStart, infoBlockEnd := getInfoStartEnd(data)
	infoBlockOrig := data[infoBlockStart:infoBlockEnd]
	infoBlockOrig = strings.TrimRight(infoBlockOrig, "\n")
	infoBlock := InfoBlock{}
	err = yaml.Unmarshal([]byte(data), &infoBlock)
	if err != nil {
		return data, false, err
	}
	// if metadata is nil, create a new map
	if infoBlock.Info.Metadata == nil {
		infoBlock.Info.Metadata = make(map[string]interface{})
	}
	// do not update if it is already present and equal
	if mr, ok := infoBlock.Info.Metadata["max-request"]; ok && mr.(int) == template.TotalRequests {
		return data, false, nil
	}
	infoBlock.Info.Metadata["max-request"] = template.TotalRequests

	var newInfoBlock bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&newInfoBlock)
	yamlEncoder.SetIndent(yamlIndentSpaces)
	err = yamlEncoder.Encode(infoBlock)
	if err != nil {
		return data, false, err
	}
	newInfoBlockData := strings.TrimSuffix(newInfoBlock.String(), "\n")
	// replace old info block with new info block
	newTemplate := strings.ReplaceAll(data, infoBlockOrig, newInfoBlockData)
	err = os.WriteFile(path, []byte(newTemplate), 0644)
	if err == nil {
		return newTemplate, true, nil
	}
	return newTemplate, false, err
}

// parseTemplate parses a template and returns the template object
func parseTemplate(catalog catalog.Catalog, templatePath string) (*templates.Template, error) {
	executorOpts := protocols.ExecutorOptions{
		Catalog: catalog,
		Options: defaultOpts,
	}
	reader, err := executorOpts.Catalog.OpenFile(templatePath)
	if err != nil {
		return nil, err
	}
	template, err := templates.ParseTemplateFromReader(reader, nil, executorOpts)
	if err != nil {
		return nil, err
	}
	return template, nil
}

// find the start and end of the info block
func getInfoStartEnd(data string) (int, int) {
	info := strings.Index(data, "info:")
	var indices []int
	for _, re := range allTagsRegex {
		// find the first occurrence of the label
		match := re.FindStringIndex(data)
		if match != nil {
			indices = append(indices, match[0])
		}
	}
	// find the first one after info block
	sort.Ints(indices)
	return info, indices[0] - 1
}
