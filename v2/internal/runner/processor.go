package runner

import (
	"context"
	"fmt"
	"net/http/cookiejar"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

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
	"github.com/remeh/sizedwaitgroup"
)

// workflowTemplates contains the initialized workflow templates per template group
type workflowTemplates struct {
	Name      string
	Templates []*workflows.Template
}

var sandboxedModules = []string{"math", "text", "rand", "fmt", "json", "base64", "hex", "enum"}

// processTemplateWithList processes a template and runs the enumeration on all the targets
func (r *Runner) processTemplateWithList(p *progress.Progress, template *templates.Template, request interface{}) bool {
	var httpExecuter *executer.HTTPExecuter
	var dnsExecuter *executer.DNSExecuter
	var err error

	// Create an executer based on the request type.
	switch value := request.(type) {
	case *requests.DNSRequest:
		dnsExecuter = executer.NewDNSExecuter(&executer.DNSOptions{
			TraceLog:      r.traceLog,
			Debug:         r.options.Debug,
			Template:      template,
			DNSRequest:    value,
			Writer:        r.output,
			JSON:          r.options.JSON,
			JSONRequests:  r.options.JSONRequests,
			NoMeta:        r.options.NoMeta,
			ColoredOutput: !r.options.NoColor,
			Colorizer:     r.colorizer,
			Decolorizer:   r.decolorizer,
			RateLimiter:   r.ratelimiter,
		})
	case *requests.BulkHTTPRequest:
		httpExecuter, err = executer.NewHTTPExecuter(&executer.HTTPOptions{
			TraceLog:         r.traceLog,
			Debug:            r.options.Debug,
			Template:         template,
			BulkHTTPRequest:  value,
			Writer:           r.output,
			Timeout:          r.options.Timeout,
			Retries:          r.options.Retries,
			ProxyURL:         r.options.ProxyURL,
			ProxySocksURL:    r.options.ProxySocksURL,
			RandomAgent:      r.options.RandomAgent,
			CustomHeaders:    r.options.CustomHeaders,
			JSON:             r.options.JSON,
			JSONRequests:     r.options.JSONRequests,
			NoMeta:           r.options.NoMeta,
			CookieReuse:      value.CookieReuse,
			ColoredOutput:    !r.options.NoColor,
			Colorizer:        &r.colorizer,
			Decolorizer:      r.decolorizer,
			StopAtFirstMatch: r.options.StopAtFirstMatch,
			PF:               r.pf,
			Dialer:           r.dialer,
			RateLimiter:      r.ratelimiter,
		})
	}

	if err != nil {
		p.Drop(request.(*requests.BulkHTTPRequest).GetRequestCount())
		gologger.Warningf("Could not create http client: %s\n", err)

		return false
	}

	var globalresult atomicboolean.AtomBool

	wg := sizedwaitgroup.New(r.options.BulkSize)

	r.hm.Scan(func(k, _ []byte) error {
		URL := string(k)
		wg.Add()
		go func(URL string) {
			defer wg.Done()

			var result *executer.Result

			if httpExecuter != nil {
				result = httpExecuter.ExecuteHTTP(p, URL)
				globalresult.Or(result.GotResults)
			}

			if dnsExecuter != nil {
				result = dnsExecuter.ExecuteDNS(p, URL)
				globalresult.Or(result.GotResults)
			}

			if result.Error != nil {
				gologger.Warningf("[%s] Could not execute step: %s\n", r.colorizer.Colorizer.BrightBlue(template.ID), result.Error)
			}
		}(URL)

		return nil
	})

	wg.Wait()

	// See if we got any results from the executers
	return globalresult.Get()
}

// ProcessWorkflowWithList coming from stdin or list of targets
func (r *Runner) processWorkflowWithList(p *progress.Progress, workflow *workflows.Workflow) bool {
	result := false

	workflowTemplatesList, err := r.preloadWorkflowTemplates(p, workflow)
	if err != nil {
		gologger.Warningf("Could not preload templates for workflow %s: %s\n", workflow.ID, err)
		return false
	}
	logicBytes := []byte(workflow.Logic)

	wg := sizedwaitgroup.New(r.options.BulkSize)
	r.hm.Scan(func(k, _ []byte) error {
		targetURL := string(k)
		wg.Add()

		go func(targetURL string) {
			defer wg.Done()

			script := tengo.NewScript(logicBytes)
			if !r.options.Sandbox {
				script.SetImports(stdlib.GetModuleMap(stdlib.AllModuleNames()...))
			} else {
				script.SetImports(stdlib.GetModuleMap(sandboxedModules...))
			}

			variables := make(map[string]*workflows.NucleiVar)
			for _, workflowTemplate := range *workflowTemplatesList {
				name := workflowTemplate.Name
				variable := &workflows.NucleiVar{Templates: workflowTemplate.Templates, URL: targetURL}
				err := script.Add(name, variable)
				if err != nil {
					gologger.Errorf("Could not initialize script for workflow '%s': %s\n", workflow.ID, err)
					continue
				}
				variables[name] = variable
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.options.MaxWorkflowDuration)*time.Minute)
			defer cancel()

			_, err := script.RunContext(ctx)
			if err != nil {
				gologger.Errorf("Could not execute workflow '%s': %s\n", workflow.ID, err)
			}

			for _, variable := range variables {
				result = !variable.IsFalsy()
				if result {
					break
				}
			}
		}(targetURL)
		return nil
	})

	wg.Wait()

	return result
}

func (r *Runner) preloadWorkflowTemplates(p *progress.Progress, workflow *workflows.Workflow) (*[]workflowTemplates, error) {
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
					TraceLog:         r.traceLog,
					Debug:            r.options.Debug,
					Writer:           r.output,
					Template:         t,
					Timeout:          r.options.Timeout,
					Retries:          r.options.Retries,
					ProxyURL:         r.options.ProxyURL,
					ProxySocksURL:    r.options.ProxySocksURL,
					RandomAgent:      r.options.RandomAgent,
					CustomHeaders:    r.options.CustomHeaders,
					JSON:             r.options.JSON,
					JSONRequests:     r.options.JSONRequests,
					CookieJar:        jar,
					ColoredOutput:    !r.options.NoColor,
					Colorizer:        &r.colorizer,
					Decolorizer:      r.decolorizer,
					PF:               r.pf,
					RateLimiter:      r.ratelimiter,
					NoMeta:           r.options.NoMeta,
					StopAtFirstMatch: r.options.StopAtFirstMatch,
					Dialer:           r.dialer,
				}
			} else if len(t.RequestsDNS) > 0 {
				template.DNSOptions = &executer.DNSOptions{
					TraceLog:      r.traceLog,
					Debug:         r.options.Debug,
					Template:      t,
					Writer:        r.output,
					JSON:          r.options.JSON,
					JSONRequests:  r.options.JSONRequests,
					ColoredOutput: !r.options.NoColor,
					Colorizer:     r.colorizer,
					Decolorizer:   r.decolorizer,
					NoMeta:        r.options.NoMeta,
					RateLimiter:   r.ratelimiter,
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
						Writer:        r.output,
						Template:      t,
						Timeout:       r.options.Timeout,
						Retries:       r.options.Retries,
						ProxyURL:      r.options.ProxyURL,
						ProxySocksURL: r.options.ProxySocksURL,
						RandomAgent:   r.options.RandomAgent,
						CustomHeaders: r.options.CustomHeaders,
						CookieJar:     jar,
						TraceLog:      r.traceLog,
					}
				} else if len(t.RequestsDNS) > 0 {
					template.DNSOptions = &executer.DNSOptions{
						Debug:    r.options.Debug,
						Template: t,
						Writer:   r.output,
						TraceLog: r.traceLog,
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
