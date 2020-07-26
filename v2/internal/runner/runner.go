package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"sync"

	tengo "github.com/d5/tengo/v2"
	"github.com/d5/tengo/v2/stdlib"
	"github.com/karrick/godirwalk"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/atomicboolean"
	"github.com/projectdiscovery/nuclei/v2/pkg/executer"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	input      string
	inputCount int64

	// output is the output file to write if any
	output      *os.File
	outputMutex *sync.Mutex

	tempFile        string
	templatesConfig *nucleiConfig
	// options contains configuration options for runner
	options *Options
	limiter chan struct{}

	// progress tracking
	progress *progress.Progress
}

// New creates a new client for running enumeration process.
func New(options *Options) (*Runner, error) {
	runner := &Runner{
		outputMutex: &sync.Mutex{},
		options:     options,
	}

	if err := runner.updateTemplates(); err != nil {
		gologger.Warningf("Could not update templates: %s\n", err)
	}
	if (len(options.Templates) == 0 || (options.Targets == "" && !options.Stdin && options.Target == "")) && options.UpdateTemplates {
		os.Exit(0)
	}

	// If we have stdin, write it to a new file
	if options.Stdin {
		tempInput, err := ioutil.TempFile("", "stdin-input-*")
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(tempInput, os.Stdin); err != nil {
			return nil, err
		}
		runner.tempFile = tempInput.Name()
		tempInput.Close()
	}
	// If we have single target, write it to a new file
	if options.Target != "" {
		tempInput, err := ioutil.TempFile("", "stdin-input-*")
		if err != nil {
			return nil, err
		}
		tempInput.WriteString(options.Target)
		runner.tempFile = tempInput.Name()
		tempInput.Close()
	}

	// Setup input, handle a list of hosts as argument
	var err error
	var input *os.File
	if options.Targets != "" {
		input, err = os.Open(options.Targets)
	} else if options.Stdin || options.Target != "" {
		input, err = os.Open(runner.tempFile)
	}
	if err != nil {
		gologger.Fatalf("Could not open targets file '%s': %s\n", options.Targets, err)
	}

	// Sanitize input and pre-compute total number of targets
	var usedInput = make(map[string]bool)
	dupeCount := 0
	sb := strings.Builder{}
	scanner := bufio.NewScanner(input)
	runner.inputCount = 0
	for scanner.Scan() {
		url := scanner.Text()
		// skip empty lines
		if len(url) == 0 {
			continue
		}
		// deduplication
		if _, ok := usedInput[url]; !ok {
			usedInput[url] = true
			runner.inputCount++
			sb.WriteString(url)
			sb.WriteString("\n")
		} else {
			dupeCount++
		}
	}
	input.Close()
	runner.input = sb.String()
	if dupeCount > 0 {
		gologger.Labelf("Supplied input was automatically deduplicated (%d removed).", dupeCount)
	}

	// Create the output file if asked
	if options.Output != "" {
		output, err := os.Create(options.Output)
		if err != nil {
			gologger.Fatalf("Could not create output file '%s': %s\n", options.Output, err)
		}
		runner.output = output
	}

	// Creates the progress tracking object
	runner.progress = progress.NewProgress(runner.options.NoColor)

	runner.limiter = make(chan struct{}, options.Threads)

	return runner, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	r.output.Close()
	os.Remove(r.tempFile)
}

func isFilePath(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

func (r *Runner) resolvePathIfRelative(path string) (string, error) {
	if r.isRelative(path) {
		newPath, err := r.resolvePath(path)
		if err != nil {
			return "", err
		}
		return newPath, nil
	}
	return path, nil
}

func isNewPath(path string, pathMap map[string]bool) bool {
	if _, already := pathMap[path]; already {
		gologger.Warningf("Skipping already specified path '%s'", path)
		return false
	}
	return true
}

// RunEnumeration sets up the input layer for giving input nuclei.
// binary and runs the actual enumeration
func (r *Runner) RunEnumeration() {
	// keeps track of processed dirs and files
	processed := make(map[string]bool)
	allTemplates := []string{}

	// parses user input, handle file/directory cases and produce a list of unique templates
	for _, t := range r.options.Templates {
		var absPath string
		var err error

		if strings.Contains(t, "*") {
			dirs := strings.Split(t, "/")
			priorDir := strings.Join(dirs[:len(dirs)-1], "/")
			absPath, err = r.resolvePathIfRelative(priorDir)
			absPath += "/" + dirs[len(dirs)-1]
		} else {
			// resolve and convert relative to absolute path
			absPath, err = r.resolvePathIfRelative(t)
		}

		if err != nil {
			gologger.Errorf("Could not find template file '%s': %s\n", t, err)
			continue
		}

		// Template input includes a wildcard
		if strings.Contains(absPath, "*") {
			matches := []string{}
			matches, err = filepath.Glob(absPath)
			if err != nil {
				gologger.Labelf("Wildcard found, but unable to glob '%s': %s\n", absPath, err)
				continue
			}

			for _, i := range matches {
				processed[i] = true
			}

			// couldn't find templates in directory
			if len(matches) == 0 {
				gologger.Labelf("Error, no templates were found with '%s'.\n", absPath)
				continue
			} else {
				gologger.Labelf("Identified %d templates\n", len(matches))
			}

			allTemplates = append(allTemplates, matches...)
		} else {
			// determine file/directory
			isFile, err := isFilePath(absPath)
			if err != nil {
				gologger.Errorf("Could not stat '%s': %s\n", absPath, err)
				continue
			}
			// test for uniqueness
			if !isNewPath(absPath, processed) {
				continue
			}
			// mark this absolute path as processed
			// - if it's a file, we'll never process it again
			// - if it's a dir, we'll never walk it again
			processed[absPath] = true

			if isFile {
				allTemplates = append(allTemplates, absPath)
			} else {
				matches := []string{}

				// Recursively walk down the Templates directory and run all the template file checks
				err = godirwalk.Walk(absPath, &godirwalk.Options{
					Callback: func(path string, d *godirwalk.Dirent) error {
						if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
							if isNewPath(path, processed) {
								matches = append(matches, path)
								processed[path] = true
							}
						}
						return nil
					},
					ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
						return godirwalk.SkipNode
					},
					Unsorted: true,
				})

				// directory couldn't be walked
				if err != nil {
					gologger.Labelf("Could not find templates in directory '%s': %s\n", absPath, err)
					continue
				}

				// couldn't find templates in directory
				if len(matches) == 0 {
					gologger.Labelf("Error, no templates were found in '%s'.\n", absPath)
					continue
				}

				allTemplates = append(allTemplates, matches...)
			}
		}
	}

	// 0 matches means no templates were found in directory
	if len(allTemplates) == 0 {
		gologger.Fatalf("Error, no templates were found.\n")
	}

	// progress tracking
	p := r.progress
	templateCount := len(allTemplates)

	// precompute total request count
	var totalRequests int64 = 0
	barIndex := 0
	parsedTemplates := []string{}

	for _, match := range allTemplates {
		t, err := r.parse(match)
		switch t.(type) {
		case *templates.Template:
			barIndex++
			template := t.(*templates.Template)
			totalRequests += template.GetHTTPRequestCount()
			totalRequests += template.GetDNSRequestCount()
			parsedTemplates = append(parsedTemplates, match)
		default:
			gologger.Errorf("Could not parse file '%s': %s\n", match, err)
		}
	}

	// ensure only successfully parsed templates are processed
	allTemplates = parsedTemplates

	// track global progress
	p.InitProgressbar(r.inputCount, templateCount, r.inputCount*totalRequests)

	var (
		wgtemplates sync.WaitGroup
		results     atomicboolean.AtomBool
	)

	for _, match := range allTemplates {
		wgtemplates.Add(1)
		go func(match string) {
			defer wgtemplates.Done()
			t, err := r.parse(match)
			switch t.(type) {
			case *templates.Template:
				template := t.(*templates.Template)
				for _, request := range template.RequestsDNS {
					results.Or(r.processTemplateWithList(p, template, request))
				}
				for _, request := range template.BulkRequestsHTTP {
					results.Or(r.processTemplateWithList(p, template, request))
				}
			case *workflows.Workflow:
				workflow := t.(*workflows.Workflow)
				r.ProcessWorkflowWithList(workflow)
			default:
				p.StartStdCapture()
				gologger.Errorf("Could not parse file '%s': %s\n", match, err)
				p.StopStdCapture()
			}
		}(match)
	}

	wgtemplates.Wait()
	p.Wait()
	p.ShowStdErr()
	p.ShowStdOut()

	if !results.Get() {
		if r.output != nil {
			outputFile := r.output.Name()
			r.output.Close()
			os.Remove(outputFile)
		}
		gologger.Infof("No results found. Happy hacking!")
	}
	return
}

// processTemplateWithList processes a template and runs the enumeration on all the targets
func (r *Runner) processTemplateWithList(p *progress.Progress, template *templates.Template, request interface{}) bool {
	// Display the message for the template
	message := fmt.Sprintf("[%s] Loaded template %s (@%s)", template.ID, template.Info.Name, template.Info.Author)
	if template.Info.Severity != "" {
		message += " [" + template.Info.Severity + "]"
	}
	p.StartStdCapture()
	gologger.Infof("%s\n", message)
	p.StopStdCapture()

	var writer *bufio.Writer
	if r.output != nil {
		writer = bufio.NewWriter(r.output)
		defer writer.Flush()
	}

	var httpExecuter *executer.HTTPExecuter
	var dnsExecuter *executer.DNSExecuter
	var err error

	// Create an executer based on the request type.
	switch value := request.(type) {
	case *requests.DNSRequest:
		dnsExecuter = executer.NewDNSExecuter(&executer.DNSOptions{
			Debug:      r.options.Debug,
			Template:   template,
			DNSRequest: value,
			Writer:     writer,
			JSON:       r.options.JSON,
		})
	case *requests.BulkHTTPRequest:
		httpExecuter, err = executer.NewHTTPExecuter(&executer.HTTPOptions{
			Debug:           r.options.Debug,
			Template:        template,
			BulkHttpRequest: value,
			Writer:          writer,
			Timeout:         r.options.Timeout,
			Retries:         r.options.Retries,
			ProxyURL:        r.options.ProxyURL,
			ProxySocksURL:   r.options.ProxySocksURL,
			CustomHeaders:   r.options.CustomHeaders,
			JSON:            r.options.JSON,
			JSONRequests:    r.options.JSONRequests,
			CookieReuse:     value.CookieReuse,
		})
	}
	if err != nil {
		p.StartStdCapture()
		gologger.Warningf("Could not create http client: %s\n", err)
		p.StopStdCapture()
		return false
	}

	var globalresult atomicboolean.AtomBool

	var wg sync.WaitGroup

	scanner := bufio.NewScanner(strings.NewReader(r.input))
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}

		r.limiter <- struct{}{}
		wg.Add(1)

		go func(URL string) {
			defer wg.Done()
			var result executer.Result

			if httpExecuter != nil {
				result = httpExecuter.ExecuteHTTP(p, URL)
				globalresult.Or(result.GotResults)
			}
			if dnsExecuter != nil {
				result = dnsExecuter.ExecuteDNS(p, URL)
				globalresult.Or(result.GotResults)
			}
			if result.Error != nil {
				p.StartStdCapture()
				gologger.Warningf("Could not execute step: %s\n", result.Error)
				p.StopStdCapture()
			}
			<-r.limiter
		}(text)
	}

	wg.Wait()

	// See if we got any results from the executers
	return globalresult.Get()
}

// ProcessWorkflowWithList coming from stdin or list of targets
func (r *Runner) ProcessWorkflowWithList(workflow *workflows.Workflow) {
	scanner := bufio.NewScanner(strings.NewReader(r.input))
	for scanner.Scan() {
		text := scanner.Text()
		if err := r.ProcessWorkflow(workflow, text); err != nil {
			gologger.Warningf("Could not run workflow for %s: %s\n", text, err)
		}
	}
}

// ProcessWorkflow towards an URL
func (r *Runner) ProcessWorkflow(workflow *workflows.Workflow, URL string) error {
	script := tengo.NewScript([]byte(workflow.Logic))
	script.SetImports(stdlib.GetModuleMap(stdlib.AllModuleNames()...))
	var jar *cookiejar.Jar
	if workflow.CookieReuse {
		var err error
		jar, err = cookiejar.New(nil)
		if err != nil {
			return err
		}
	}
	for name, value := range workflow.Variables {
		var writer *bufio.Writer
		if r.output != nil {
			writer = bufio.NewWriter(r.output)
			defer writer.Flush()
		}

		// Check if the template is an absolute path or relative path.
		// If the path is absolute, use it. Otherwise,
		if r.isRelative(value) {
			newPath, err := r.resolvePath(value)
			if err != nil {
				return err
			}
			value = newPath
		}

		// Single yaml provided
		var templatesList []*workflows.Template
		if strings.HasSuffix(value, ".yaml") {
			t, err := templates.Parse(value)
			if err != nil {
				return err
			}
			template := &workflows.Template{}
			if len(t.BulkRequestsHTTP) > 0 {
				template.HTTPOptions = &executer.HTTPOptions{
					Debug:         r.options.Debug,
					Writer:        writer,
					Template:      t,
					Timeout:       r.options.Timeout,
					Retries:       r.options.Retries,
					ProxyURL:      r.options.ProxyURL,
					ProxySocksURL: r.options.ProxySocksURL,
					CustomHeaders: r.options.CustomHeaders,
					CookieJar:     jar,
				}
			} else if len(t.RequestsDNS) > 0 {
				template.DNSOptions = &executer.DNSOptions{
					Debug:    r.options.Debug,
					Template: t,
					Writer:   writer,
				}
			}
			if template.DNSOptions != nil || template.HTTPOptions != nil {
				templatesList = append(templatesList, template)
			}
		} else {
			matches := []string{}

			err := godirwalk.Walk(value, &godirwalk.Options{
				Callback: func(path string, d *godirwalk.Dirent) error {
					if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
						matches = append(matches, path)
					}
					return nil
				},
				ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
					return godirwalk.SkipNode
				},
				Unsorted: true,
			})
			if err != nil {
				return err
			}
			// 0 matches means no templates were found in directory
			if len(matches) == 0 {
				return errors.New("no match found in the directory")
			}

			for _, match := range matches {
				t, err := templates.Parse(match)
				if err != nil {
					return err
				}
				template := &workflows.Template{}
				if len(t.BulkRequestsHTTP) > 0 {
					template.HTTPOptions = &executer.HTTPOptions{
						Debug:         r.options.Debug,
						Writer:        writer,
						Template:      t,
						Timeout:       r.options.Timeout,
						Retries:       r.options.Retries,
						ProxyURL:      r.options.ProxyURL,
						ProxySocksURL: r.options.ProxySocksURL,
						CustomHeaders: r.options.CustomHeaders,
						CookieJar:     jar,
					}
				} else if len(t.RequestsDNS) > 0 {
					template.DNSOptions = &executer.DNSOptions{
						Debug:    r.options.Debug,
						Template: t,
						Writer:   writer,
					}
				}
				if template.DNSOptions != nil || template.HTTPOptions != nil {
					templatesList = append(templatesList, template)
				}
			}
		}

		script.Add(name, &workflows.NucleiVar{Templates: templatesList, URL: URL})
	}

	_, err := script.RunContext(context.Background())
	if err != nil {
		gologger.Errorf("Could not execute workflow '%s': %s\n", workflow.ID, err)
		return err
	}
	return nil
}

func (r *Runner) parse(file string) (interface{}, error) {
	// check if it's a template
	template, errTemplate := templates.Parse(file)
	if errTemplate == nil {
		return template, nil
	}

	// check if it's a workflow
	workflow, errWorkflow := workflows.Parse(file)
	if errWorkflow == nil {
		return workflow, nil
	}

	if errTemplate != nil {
		return nil, errTemplate
	}
	if errWorkflow != nil {
		return nil, errWorkflow
	}
	return nil, errors.New("unknown error occured")
}
