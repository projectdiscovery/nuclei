package runner

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"io"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zlib"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/runner/nucleicloud"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"go.uber.org/atomic"
)

const DDMMYYYYhhmmss = "2006-01-02 15:04:05"

// runStandardEnumeration runs standard enumeration
func (r *Runner) runStandardEnumeration(executerOpts protocols.ExecuterOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.AutomaticScan {
		return r.executeSmartWorkflowInput(executerOpts, store, engine)
	}
	return r.executeTemplatesInput(store, engine)
}

// Get all the scan lists for a user/apikey.
func (r *Runner) getScanList() error {
	items, err := r.cloudClient.GetScans()
	loc, _ := time.LoadLocation("Local")

	for _, v := range items {
		status := "FINISHED"
		t := v.FinishedAt
		duration := t.Sub(v.CreatedAt)
		if !v.Finished {
			status = "RUNNING"
			t = time.Now().UTC()
			duration = t.Sub(v.CreatedAt)
		}

		val := v.CreatedAt.In(loc).Format(DDMMYYYYhhmmss)

		gologger.Silent().Msgf("%s [%s] [STATUS: %s] [MATCHED: %d] [TARGETS: %d] [TEMPLATES: %d] [DURATION: %s]\n", v.Id, val, status, v.Matches, v.Targets, v.Templates, duration)
	}
	return err
}

func (r *Runner) deleteScan(id string) error {
	deleted, err := r.cloudClient.DeleteScan(id)
	if !deleted.OK {
		gologger.Info().Msgf("Error in deleting the scan %s.", id)
	} else {
		gologger.Info().Msgf("Scan deleted %s.", id)
	}
	return err
}

func (r *Runner) getResults(id string) error {
	err := r.cloudClient.GetResults(id, func(re *output.ResultEvent) {
		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", outputErr)
		}
	}, false)
	return err
}

// runCloudEnumeration runs cloud based enumeration
func (r *Runner) runCloudEnumeration(store *loader.Store, nostore bool) (*atomic.Bool, error) {
	now := time.Now()
	defer func() {
		gologger.Info().Msgf("Scan execution took %s", time.Since(now))
	}()
	results := &atomic.Bool{}

	// TODO: Add payload file and workflow support for private templates
	catalogChecksums := nucleicloud.ReadCatalogChecksum()

	targets := make([]string, 0, r.hmapInputProvider.Count())
	r.hmapInputProvider.Scan(func(value string) bool {
		targets = append(targets, value)
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

	taskID, err := r.cloudClient.AddScan(&nucleicloud.AddScanRequest{
		RawTargets:       targets,
		PublicTemplates:  templates,
		PrivateTemplates: privateTemplates,
		IsTemporary:      nostore,
	})
	if err != nil {
		return results, err
	}
	gologger.Info().Msgf("Created task with ID: %s", taskID)
	time.Sleep(3 * time.Second)

	err = r.cloudClient.GetResults(taskID, func(re *output.ResultEvent) {
		results.CompareAndSwap(false, true)

		if outputErr := r.output.Write(re); outputErr != nil {
			gologger.Warning().Msgf("Could not write output: %s", err)
		}
		if r.issuesClient != nil {
			if err := r.issuesClient.CreateIssue(re); err != nil {
				gologger.Warning().Msgf("Could not create issue on tracker: %s", err)
			}
		}
	}, true)
	return results, err
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
