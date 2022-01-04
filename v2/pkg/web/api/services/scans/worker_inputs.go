package scans

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

// inputProviderFromRequest returns an input provider from scan request
func (s *ScanService) inputProviderFromRequest(inputsList []string) (core.InputProvider, error) {
	tempfile, err := ioutil.TempFile("", "nuclei-input-*")
	if err != nil {
		return nil, err
	}
	defer tempfile.Close()

	for _, input := range inputsList {
		parsedID, err := strconv.ParseInt(input, 10, 64)
		if err != nil {
			_, _ = tempfile.WriteString(input)
			_, _ = tempfile.WriteString("\n")
		} else {
			target, err := s.db.GetTarget(context.Background(), parsedID)
			if err != nil {
				return nil, err
			}
			read, err := s.target.Read(target.Internalid)
			if err != nil {
				return nil, err
			}
			_, _ = io.Copy(tempfile, read)
			_ = read.Close()
		}
	}
	return inputs.NewFileInputProvider(tempfile.Name()), nil
}

// storeTemplatesFromRequest writes templates from db to a temporary
// on disk directory for the duration of the scan.
func (s *ScanService) storeTemplatesFromRequest(templatesList []string) (string, []string, []string, error) {
	directory, err := ioutil.TempDir("", "nuclei-templates-*")
	if err != nil {
		return "", nil, nil, err
	}
	var templates, workflows []string
	for _, template := range templatesList {
		resp, err := s.db.GetTemplatesForScan(context.Background(), template)
		if err != nil {
			return "", nil, nil, err
		}

		for _, value := range resp {
			if strings.Contains(value.Contents, "workflow:") {
				workflows = append(workflows, value.Path)
			} else {
				templates = append(templates, value.Path)
			}
			directoryBase := filepath.Dir(value.Path)
			_ = os.MkdirAll(path.Join(directory, directoryBase), os.ModePerm)

			if err = ioutil.WriteFile(path.Join(directory, value.Path), []byte(value.Contents), os.ModePerm); err != nil {
				return "", nil, nil, err
			}
		}
	}
	return directory, templates, workflows, nil
}

// dbPayloadLoader loads payloads from db
type dbPayloadLoader struct {
	db dbsql.Querier
}

func (d *dbPayloadLoader) Load(name string) ([]string, error) {
	contents, err := d.db.GetTemplateContents(context.Background(), name)
	if err != nil {
		return nil, errors.Wrap(err, "could not get payload contents from db")
	}
	parts := strings.Split(contents, "\n")
	return parts, nil
}
