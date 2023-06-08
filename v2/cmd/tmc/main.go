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
	// temaplateman api base url
	//tmBaseUrl = "https://tm.nuclei.sh"
	tmBaseUrl = "http://localhost:1000"
)

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

var idRegex = regexp.MustCompile("id: ([C|c][V|v][E|e]-[0-9]+-[0-9]+)")

type options struct {
	input   string
	debug   bool
	enhance bool
	format  bool
	lint    bool
}

func main() {
	opts := options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`TemplateMan CLI is baisc utility built on the TemplateMan API to standardize nuclei templates.`)

	flagSet.CreateGroup("Input", "input",
		flagSet.StringVarP(&opts.input, "input", "i", "", "Templates to annotate"),
	)

	flagSet.CreateGroup("Config", "config",
		flagSet.BoolVarP(&opts.enhance, "enhance", "e", false, "enhance given nuclei template"),
		flagSet.BoolVarP(&opts.format, "format", "f", false, "format given nuclei template"),
		flagSet.BoolVarP(&opts.lint, "lint", "l", false, "lint given nuclei template"),
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

		if opts.lint {
			lint, err := lintTemplate(dataString)
			if err != nil {
				gologger.Info().Label("lint").Msg(formatErrMsg(path, err, opts.debug))
			}
			if lint {
				gologger.Info().Label("lint").Msgf("✅ lint template: %s\n", path)
			}
		}

		if opts.format {
			formatedTemplateData, err := formatTemplate(dataString)
			if err != nil {
				gologger.Info().Label("format").Msg(formatErrMsg(path, err, opts.debug))
			} else {
				_ = os.WriteFile(path, []byte(formatedTemplateData), 0644)
				dataString = formatedTemplateData
				gologger.Info().Label("format").Msgf("✅ formatted template: %s\n", path)
			}
		}

		if opts.enhance {
			// try to fill max-requests
			dataString, err = parseAndAddMaxRequests(templateCatalog, path, dataString)
			if err != nil {
				gologger.Info().Msgf(formatErrMsg(path, err, opts.debug))
			}
			gologger.Info().Label("max-request").Msgf("✅ updated template: %s\n", path)
			// currently enhance api only supports cve-id's
			matches := idRegex.FindAllStringSubmatch(dataString, 1)
			if len(matches) == 0 {
				continue
			}
			enhancedTemplateData, err := enhanceTemplate(dataString)
			if err != nil {
				gologger.Info().Label("enhance").Msg(formatErrMsg(path, err, opts.debug))
				continue
			}
			_ = os.WriteFile(path, []byte(enhancedTemplateData), 0644)
			gologger.Info().Label("enhance").Msgf("✅ updated template: %s\n", path)
		}
	}
	return nil
}

func formatErrMsg(path string, err error, debug bool) string {
	msg := fmt.Sprintf("❌ template: %s\n", path)
	if debug {
		msg = fmt.Sprintf("❌ template: %s err: %s\n", path, err)
	}
	return msg
}

// enhanceTemplateData enhances template data using templateman
// ref: https://github.com/projectdiscovery/templateman/blob/main/templateman-rest-api/README.md#enhance-api
func enhanceTemplate(data string) (string, error) {
	resp, err := retryablehttp.DefaultClient().Post(fmt.Sprintf("%s/enhance", tmBaseUrl), "application/x-yaml", strings.NewReader(data))
	if err != nil {
		return data, err
	}
	if resp.StatusCode != 200 {
		return data, errorutil.New("unexpected status code: %v", resp.Status)
	}
	var templateResp TemplateResp
	if err := json.NewDecoder(resp.Body).Decode(&templateResp); err != nil {
		return data, err
	}
	if templateResp.Enhance || strings.TrimSpace(templateResp.Enhanced) != "" {
		return templateResp.Enhanced, nil
	}
	if templateResp.ValidateErrorCount > 0 {
		if len(templateResp.ValidateError) > 0 {
			return data, errorutil.NewWithTag("validate", templateResp.ValidateError[0].Message+": at line %v", templateResp.ValidateError[0].Mark.Line)
		}
		return data, errorutil.New("validation failed").WithTag("validate")
	}
	if templateResp.Error.Name != "" {
		return data, errorutil.New(templateResp.Error.Name)
	}
	if strings.TrimSpace(templateResp.Enhanced) == "" && !templateResp.Lint {
		if templateResp.LintError.Reason != "" {
			return data, errorutil.NewWithTag("lint", templateResp.LintError.Reason+" : at line %v", templateResp.LintError.Mark.Line)
		}
		return data, errorutil.NewWithTag("lint", "at line: %v", templateResp.LintError.Mark.Line)
	}
	return data, errorutil.New("template enhance failed")
}

// formatTemplateData formats template data using templateman api
func formatTemplate(data string) (string, error) {
	resp, err := retryablehttp.DefaultClient().Post(fmt.Sprintf("%s/format", tmBaseUrl), "application/x-yaml", strings.NewReader(data))
	if err != nil {
		return data, err
	}
	if resp.StatusCode != 200 {
		return data, errorutil.New("unexpected status code: %v", resp.Status)
	}
	var templateResp TemplateResp
	if err := json.NewDecoder(resp.Body).Decode(&templateResp); err != nil {
		return data, err
	}
	if templateResp.Format || strings.TrimSpace(templateResp.Updated) != "" {
		return templateResp.Updated, nil
	}
	if templateResp.ValidateErrorCount > 0 {
		if len(templateResp.ValidateError) > 0 {
			return data, errorutil.NewWithTag("validate", templateResp.ValidateError[0].Message+": at line %v", templateResp.ValidateError[0].Mark.Line)
		}
		return data, errorutil.New("validation failed").WithTag("validate")
	}
	if templateResp.Error.Name != "" {
		return data, errorutil.New(templateResp.Error.Name)
	}
	if strings.TrimSpace(templateResp.Updated) == "" && !templateResp.Lint {
		if templateResp.LintError.Reason != "" {
			return data, errorutil.NewWithTag("lint", templateResp.LintError.Reason+" : at line %v", templateResp.LintError.Mark.Line)
		}
		return data, errorutil.NewWithTag("lint", "at line: %v", templateResp.LintError.Mark.Line)
	}
	return data, errorutil.New("template format failed")
}

// lintTemplateData lints template data using templateman api
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

// parseAndAddMaxRequests parses and adds max requests to templates
func parseAndAddMaxRequests(catalog catalog.Catalog, path, data string) (string, error) {
	template, err := parseTemplate(catalog, path)
	if err != nil {
		return data, err
	}
	if template.TotalRequests < 1 {
		return data, nil
	}
	// Marshal the updated info block back to YAML.
	infoBlockStart, infoBlockEnd := getInfoStartEnd(data)
	infoBlockOrig := data[infoBlockStart:infoBlockEnd]
	infoBlockOrig = strings.TrimRight(infoBlockOrig, "\n")
	infoBlock := InfoBlock{}
	err = yaml.Unmarshal([]byte(data), &infoBlock)
	if err != nil {
		return data, err
	}
	// if metadata is nil, create a new map
	if infoBlock.Info.Metadata == nil {
		infoBlock.Info.Metadata = make(map[string]interface{})
	}
	// do not update if it is already present and equal
	if mr, ok := infoBlock.Info.Metadata["max-request"]; ok && mr.(int) == template.TotalRequests {
		return data, nil
	}
	infoBlock.Info.Metadata["max-request"] = template.TotalRequests

	var newInfoBlock bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&newInfoBlock)
	yamlEncoder.SetIndent(yamlIndentSpaces)
	err = yamlEncoder.Encode(infoBlock)
	if err != nil {
		return data, err
	}
	newInfoBlockData := strings.TrimSuffix(newInfoBlock.String(), "\n")
	// replace old info block with new info block
	newTemplate := strings.ReplaceAll(data, infoBlockOrig, newInfoBlockData)
	err = os.WriteFile(path, []byte(newTemplate), 0644)
	return newTemplate, err
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
