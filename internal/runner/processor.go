package runner

import (
	"bufio"
	"context"
	"fmt"
	"net/http/cookiejar"
	"os"
	"path"
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

// workflowTemplates contains the initialized workflow templates per template group
type workflowTemplates struct {
	Name      string
	Templates []*workflows.Template
}

// processTemplateWithList processes a template and runs the enumeration on all the targets
func (r *Runner) processTemplateWithList(ctx context.Context, p progress.IProgress, template *templates.Template, request interface{}) bool {
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
			Debug:         r.options.Debug,
			Template:      template,
			DNSRequest:    value,
			Writer:        writer,
			JSON:          r.options.JSON,
			JSONRequests:  r.options.JSONRequests,
			ColoredOutput: !r.options.NoColor,
			Colorizer:     r.colorizer,
			Decolorizer:   r.decolorizer,
		})
	case *requests.BulkHTTPRequest:
		httpExecuter, err = executer.NewHTTPExecuter(&executer.HTTPOptions{
			Debug:           r.options.Debug,
			Template:        template,
			BulkHTTPRequest: value,
			Writer:          writer,
			Timeout:         r.options.Timeout,
			Retries:         r.options.Retries,
			ProxyURL:        r.options.ProxyURL,
			ProxySocksURL:   r.options.ProxySocksURL,
			CustomHeaders:   r.options.CustomHeaders,
			JSON:            r.options.JSON,
			JSONRequests:    r.options.JSONRequests,
			CookieReuse:     value.CookieReuse,
			ColoredOutput:   !r.options.NoColor,
			Colorizer:       r.colorizer,
			Decolorizer:     r.decolorizer,
		})
	}

	if err != nil {
		p.Drop(request.(*requests.BulkHTTPRequest).GetRequestCount())
		gologger.Warningf("Could not create http client: %s\n", err)

		return false
	}

	var globalresult atomicboolean.AtomBool

	var wg sync.WaitGroup

	scanner := bufio.NewScanner(strings.NewReader(r.input))
	for scanner.Scan() {
		text := scanner.Text()

		r.limiter <- struct{}{}

		wg.Add(1)

		go func(URL string) {
			defer wg.Done()

			var result executer.Result

			if httpExecuter != nil {
				result = httpExecuter.ExecuteHTTP(ctx, p, URL)
				globalresult.Or(result.GotResults)
			}

			if dnsExecuter != nil {
				result = dnsExecuter.ExecuteDNS(p, URL)
				globalresult.Or(result.GotResults)
			}

			if result.Error != nil {
				gologger.Warningf("Could not execute step: %s\n", result.Error)
			}

			<-r.limiter
		}(text)
	}

	wg.Wait()

	// See if we got any results from the executers
	return globalresult.Get()
}

// ProcessWorkflowWithList coming from stdin or list of targets
func (r *Runner) processWorkflowWithList(p progress.IProgress, workflow *workflows.Workflow) {
	workflowTemplatesList, err := r.preloadWorkflowTemplates(p, workflow)
	if err != nil {
		gologger.Warningf("Could not preload templates for workflow %s: %s\n", workflow.ID, err)

		return
	}

	logicBytes := []byte(workflow.Logic)

	var wg sync.WaitGroup

	scanner := bufio.NewScanner(strings.NewReader(r.input))
	for scanner.Scan() {
		targetURL := scanner.Text()
		r.limiter <- struct{}{}

		wg.Add(1)

		go func(targetURL string) {
			defer wg.Done()

			script := tengo.NewScript(logicBytes)
			script.SetImports(stdlib.GetModuleMap(stdlib.AllModuleNames()...))

			for _, workflowTemplate := range *workflowTemplatesList {
				err := script.Add(workflowTemplate.Name, &workflows.NucleiVar{Templates: workflowTemplate.Templates, URL: targetURL})
				if err != nil {
					gologger.Errorf("Could not initialize script for workflow '%s': %s\n", workflow.ID, err)

					continue
				}
			}

			_, err := script.RunContext(context.Background())
			if err != nil {
				gologger.Errorf("Could not execute workflow '%s': %s\n", workflow.ID, err)
			}

			<-r.limiter
		}(targetURL)
	}

	wg.Wait()
}

func (r *Runner) preloadWorkflowTemplates(p progress.IProgress, workflow *workflows.Workflow) (*[]workflowTemplates, error) {
	var jar *cookiejar.Jar

	if workflow.CookieReuse {
		var err error
		jar, err = cookiejar.New(nil)

		if err != nil {
			return nil, err
		}
	}

	// Single yaml provided
	var wflTemplatesList []workflowTemplates

	for name, value := range workflow.Variables {
		var writer *bufio.Writer
		if r.output != nil {
			writer = bufio.NewWriter(r.output)
			defer writer.Flush()
		}

		// Check if the template is an absolute path or relative path.
		// If the path is absolute, use it. Otherwise,
		if isRelative(value) {
			newPath, err := r.resolvePath(value)
			if err != nil {
				newPath, err = resolvePathWithBaseFolder(filepath.Dir(workflow.GetPath()), value)
				if err != nil {
					return nil, err
				}
			}

			value = newPath
		}

		var wtlst []*workflows.Template

		if strings.HasSuffix(value, ".yaml") {
			t, err := templates.Parse(value)
			if err != nil {
				return nil, err
			}

			template := &workflows.Template{Progress: p}
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
					ColoredOutput: !r.options.NoColor,
					Colorizer:     r.colorizer,
					Decolorizer:   r.decolorizer,
				}
			} else if len(t.RequestsDNS) > 0 {
				template.DNSOptions = &executer.DNSOptions{
					Debug:         r.options.Debug,
					Template:      t,
					Writer:        writer,
					ColoredOutput: !r.options.NoColor,
					Colorizer:     r.colorizer,
					Decolorizer:   r.decolorizer,
				}
			}

			if template.DNSOptions != nil || template.HTTPOptions != nil {
				wtlst = append(wtlst, template)
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
				return nil, err
			}

			// 0 matches means no templates were found in directory
			if len(matches) == 0 {
				return nil, fmt.Errorf("no match found in the directory %s", value)
			}

			for _, match := range matches {
				t, err := templates.Parse(match)
				if err != nil {
					return nil, err
				}
				template := &workflows.Template{Progress: p}
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
					wtlst = append(wtlst, template)
				}
			}
		}

		wflTemplatesList = append(wflTemplatesList, workflowTemplates{Name: name, Templates: wtlst})
	}

	return &wflTemplatesList, nil
}

func resolvePathWithBaseFolder(baseFolder, templateName string) (string, error) {
	templatePath := path.Join(baseFolder, templateName)
	if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
		gologger.Debugf("Found template in current directory: %s\n", templatePath)
		return templatePath, nil
	}

	return "", fmt.Errorf("no such path found: %s", templateName)
}
