package runner

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zlib"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner/nucleicloud"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"go.uber.org/atomic"
)

// runStandardEnumeration runs standard enumeration
func (r *Runner) runStandardEnumeration(executerOpts protocols.ExecuterOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.AutomaticScan {
		return r.executeSmartWorkflowInput(executerOpts, store, engine)
	}
	return r.executeTemplatesInput(store, engine)
}

// runCloudEnumeration runs cloud based enumeration
func (r *Runner) runCloudEnumeration(store *loader.Store, cloudTemplates, cloudTargets []string, nostore bool, limit int) (*atomic.Bool, error) {
	count := &atomic.Int64{}
	now := time.Now()
	defer func() {
		gologger.Info().Msgf("Scan execution took %s and found %d results", time.Since(now), count.Load())
	}()
	results := &atomic.Bool{}

	// TODO: Add payload file and workflow support for private templates
	catalogChecksums := nucleicloud.ReadCatalogChecksum()

	targets := make([]string, 0, r.hmapInputProvider.Count())
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		targets = append(targets, value.Input)
		return true
	})
	templates := make([]string, 0, len(store.Templates()))
	privateTemplates := make(map[string]string)

	for _, template := range store.Templates() {
		data, _ := os.ReadFile(template.Path)
		h := sha1.New()
		_, _ = io.Copy(h, bytes.NewReader(data))
		newhash := hex.EncodeToString(h.Sum(nil))

		templateRelativePath := getTemplateRelativePath(template.Path)
		if hash, ok := catalogChecksums[templateRelativePath]; ok || newhash == hash {
			templates = append(templates, templateRelativePath)
		} else {
			privateTemplates[filepath.Base(template.Path)] = gzipBase64EncodeData(data)
		}
	}

	input := &runCloudEnumerationInput{
		store:            store,
		nostore:          nostore,
		limit:            limit,
		targets:          targets,
		templates:        templates,
		cloudTargets:     cloudTargets,
		cloudTemplates:   cloudTemplates,
		privateTemplates: privateTemplates,
		results:          results,
		count:            count,
	}
	// Run fast positive negative scanning if dash option specified
	if r.options.Dash {
		dashErr := r.runCloudEnumerationScanDash(input)
		return input.results, dashErr
	}
	if err := r.runCloudEnumerationScan(input); err != nil {
		return input.results, err
	}
	return input.results, nil
}

type runCloudEnumerationInput struct {
	store            *loader.Store
	nostore          bool
	limit            int
	targets          []string
	templates        []string
	cloudTargets     []string
	cloudTemplates   []string
	privateTemplates map[string]string
	results          *atomic.Bool
	count            *atomic.Int64
}

// runCloudEnumerationScan runs cloud enumeration scan
func (r *Runner) runCloudEnumerationScan(input *runCloudEnumerationInput) error {
	taskID, err := r.cloudClient.AddScan(&nucleicloud.AddScanRequest{
		RawTargets:       input.targets,
		PublicTemplates:  input.templates,
		CloudTargets:     input.cloudTargets,
		CloudTemplates:   input.cloudTemplates,
		PrivateTemplates: input.privateTemplates,
		IsTemporary:      input.nostore,
		Filtering:        getCloudFilteringFromOptions(r.options),
	})
	if err != nil {
		return err
	}
	gologger.Info().Msgf("Created task with ID: %d", taskID)
	if input.nostore {
		gologger.Info().Msgf("Cloud scan storage: disabled")
	}
	time.Sleep(3 * time.Second)

	scanResponse, err := r.cloudClient.GetScan(taskID)
	if err != nil {
		return errors.Wrap(err, "could not get scan status")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start progress logging for the created scan
	if r.progress != nil {
		ticker := time.NewTicker(time.Duration(r.options.StatsInterval) * time.Second)
		r.progress.Init(r.hmapInputProvider.Count(), int(scanResponse.Templates), int64(scanResponse.Total))
		go func() {
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if scanResponse, err := r.cloudClient.GetScan(taskID); err == nil {
						r.progress.SetRequests(uint64(scanResponse.Current))
					}
				}
			}
		}()
	}

	err = r.cloudClient.GetResults(taskID, true, input.limit, func(re *output.ResultEvent) {
		r.progress.IncrementMatched()
		input.results.CompareAndSwap(false, true)
		_ = input.count.Inc()

		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", err)
		}
		if r.issuesClient != nil {
			if err := r.issuesClient.CreateIssue(re); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
	})
	return err
}

func getTemplateRelativePath(templatePath string) string {
	splitted := strings.SplitN(templatePath, "nuclei-templates", 2)
	if len(splitted) < 2 {
		return ""
	}
	return strings.TrimPrefix(splitted[1], "/")
}

func gzipBase64EncodeData(data []byte) string {
	var buf bytes.Buffer
	writer, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	_, _ = writer.Write(data)
	_ = writer.Close()
	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	return encoded
}

func getCloudFilteringFromOptions(options *types.Options) *nucleicloud.AddScanRequestConfiguration {
	return &nucleicloud.AddScanRequestConfiguration{
		Authors:           options.Authors,
		Tags:              options.Tags,
		ExcludeTags:       options.ExcludeTags,
		IncludeTags:       options.IncludeTags,
		IncludeIds:        options.IncludeIds,
		ExcludeIds:        options.ExcludeIds,
		IncludeTemplates:  options.IncludeTemplates,
		ExcludedTemplates: options.ExcludedTemplates,
		ExcludeMatchers:   options.ExcludeMatchers,
		Severities:        options.Severities,
		ExcludeSeverities: options.ExcludeSeverities,
		Protocols:         options.Protocols,
		ExcludeProtocols:  options.ExcludeProtocols,
		IncludeConditions: options.IncludeConditions,
	}
}

type dashScanInput struct {
	target       string
	template     string
	templateType string
}

// runCloudEnumerationScanDash runs cloud enumeration scan using dash service
// for positive/negative output testing.
func (r *Runner) runCloudEnumerationScanDash(enumInput *runCloudEnumerationInput) error {
	concurrency := r.options.BulkSize * r.options.TemplateThreads
	dashScanInputChan := make(chan dashScanInput, concurrency)

	gologger.Info().Msgf("Running scan using dash API with concurrency %d", concurrency)
	wg := &sync.WaitGroup{}
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			for input := range dashScanInputChan {
				resp, err := r.cloudClient.RunDashGetTemplate(input.target, input.template, input.templateType)
				if err != nil {
					gologger.Warning().Msgf("Could not run template %s on %s: %s", input.template, input.target, err)
					continue
				}
				if resp.Status == "matched" {
					enumInput.results.CompareAndSwap(false, true)
					if err := r.output.Write(&output.ResultEvent{
						Matched:          resp.Target,
						TemplateID:       resp.Template,
						ExtractedResults: []string{resp.Status},
					}); err != nil {
						gologger.Warning().Msgf("Could not write output: %s", input.target, err)
					}
				}
			}
			wg.Done()
		}()
	}
	for _, template := range enumInput.templates {
		for _, target := range enumInput.targets {
			dashScanInputChan <- dashScanInput{target: target, template: template, templateType: "public"}
		}
	}
	for _, template := range enumInput.cloudTemplates {
		for _, target := range enumInput.targets {
			dashScanInputChan <- dashScanInput{target: target, template: template, templateType: "cloud"}
		}
	}
	close(dashScanInputChan)
	wg.Wait()
	return nil
}
