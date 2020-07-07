package runner

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/google/go-github/v32/github"
	jsoniter "github.com/json-iterator/go"
	"github.com/projectdiscovery/gologger"
)

// nucleiConfig contains some configuration options for nuclei
type nucleiConfig struct {
	TemplatesDirectory string    `json:"templates-directory,omitempty"`
	CurrentVersion     string    `json:"current-version,omitempty"`
	LastChecked        time.Time `json:"last-checked,omitempty"`
}

// nucleiConfigFilename is the filename of nuclei configuration file.
const nucleiConfigFilename = ".nuclei-config.json"

var reVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)

// readConfiguration reads the nuclei configuration file from disk.
func (r *Runner) readConfiguration() (*nucleiConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	templatesConfigFile := path.Join(home, nucleiConfigFilename)
	file, err := os.Open(templatesConfigFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &nucleiConfig{}
	if err = jsoniter.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}

// readConfiguration reads the nuclei configuration file from disk.
func (r *Runner) writeConfiguration(config *nucleiConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	templatesConfigFile := path.Join(home, nucleiConfigFilename)
	file, err := os.OpenFile(templatesConfigFile, os.O_WRONLY|os.O_CREATE, 0777)
	if err != nil {
		return err
	}
	defer file.Close()

	if err = jsoniter.NewEncoder(file).Encode(config); err != nil {
		return err
	}
	return nil
}

// updateTemplates checks if the default list of nuclei-templates
// exist in the users home directory, if not the latest revision
// is downloaded from github.
//
// If the path exists but is not latest, the new version is downloaded
// from github and replaced with the templates directory.
func (r *Runner) updateTemplates() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	templatesConfigFile := path.Join(home, nucleiConfigFilename)
	if _, err := os.Stat(templatesConfigFile); !os.IsNotExist(err) {
		config, err := r.readConfiguration()
		if err != nil {
			return err
		}
		r.templatesConfig = config
	}

	if r.templatesConfig == nil || (r.options.TemplatesDirectory != "" && r.templatesConfig.TemplatesDirectory != r.options.TemplatesDirectory) {
		if !r.options.UpdateTemplates {
			gologger.Labelf("nuclei-templates are not installed, use update-templates flag.\n")
			return nil
		}

		// Use custom location if user has given a template directory
		if r.options.TemplatesDirectory != "" {
			home = r.options.TemplatesDirectory
		}
		r.templatesConfig = &nucleiConfig{TemplatesDirectory: path.Join(home, "nuclei-templates"), LastChecked: time.Now()}
		os.RemoveAll(r.templatesConfig.TemplatesDirectory)

		// Download the repository and also write the revision to a HEAD file.
		version, asset, err := r.getLatestReleaseFromGithub()
		if err != nil {
			return err
		}

		gologger.Verbosef("Downloading nuclei-templates (v%s) to %s\n", "update-templates", version.String(), r.templatesConfig.TemplatesDirectory)

		if err = r.downloadReleaseAndUnzip(asset.GetZipballURL()); err != nil {
			return err
		}
		r.templatesConfig.CurrentVersion = version.String()
		if err = r.writeConfiguration(r.templatesConfig); err != nil {
			return err
		}

		gologger.Infof("Successfully downloaded nuclei-templates (v%s). Enjoy!\n", version.String())
		return nil
	}

	// Check if last checked is more than 24 hours.
	// If not, return since we don't want to do anything now.
	if time.Now().Sub(r.templatesConfig.LastChecked) < 24*time.Hour && !r.options.UpdateTemplates {
		return nil
	}
	r.templatesConfig.LastChecked = time.Now()

	// Get the configuration currently on disk.
	verText := r.templatesConfig.CurrentVersion
	indices := reVersion.FindStringIndex(verText)
	if indices == nil {
		return fmt.Errorf("invalid release found with tag %s", err)
	}
	if indices[0] > 0 {
		verText = verText[indices[0]:]
	}
	oldVersion, err := semver.Make(verText)
	if err != nil {
		return err
	}

	version, asset, err := r.getLatestReleaseFromGithub()
	if err != nil {
		return err
	}

	if version.EQ(oldVersion) {
		gologger.Labelf("Latest version of nuclei-templates installed: v%s\n", oldVersion.String())
		return r.writeConfiguration(r.templatesConfig)
	}
	if version.GT(oldVersion) {
		if !r.options.UpdateTemplates {
			gologger.Labelf("You're using outdated nuclei-templates. Latest v%s\n", version.String())
			return r.writeConfiguration(r.templatesConfig)
		}
		if r.options.TemplatesDirectory != "" {
			home = r.options.TemplatesDirectory
			r.templatesConfig.TemplatesDirectory = path.Join(home, "nuclei-templates")
		}
		r.templatesConfig.CurrentVersion = version.String()
		os.RemoveAll(r.templatesConfig.TemplatesDirectory)

		gologger.Verbosef("Downloading nuclei-templates (v%s) to %s\n", "update-templates", version.String(), r.templatesConfig.TemplatesDirectory)

		if err = r.downloadReleaseAndUnzip(asset.GetZipballURL()); err != nil {
			return err
		}
		if err = r.writeConfiguration(r.templatesConfig); err != nil {
			return err
		}
		gologger.Infof("Successfully updated nuclei-templates (v%s). Enjoy!\n", version.String())
	}
	return nil
}

const (
	userName = "projectdiscovery"
	repoName = "nuclei-templates"
)

// getLatestReleaseFromGithub returns the latest release from github
func (r *Runner) getLatestReleaseFromGithub() (semver.Version, *github.RepositoryRelease, error) {
	client := github.NewClient(nil)

	rels, _, err := client.Repositories.ListReleases(context.Background(), userName, repoName, nil)
	if err != nil {
		return semver.Version{}, nil, err
	}

	// Find the most recent version based on semantic versioning.
	var latestRelease semver.Version
	var latestPublish *github.RepositoryRelease
	for _, release := range rels {
		verText := release.GetTagName()
		indices := reVersion.FindStringIndex(verText)
		if indices == nil {
			return semver.Version{}, nil, fmt.Errorf("invalid release found with tag %s", err)
		}
		if indices[0] > 0 {
			verText = verText[indices[0]:]
		}
		ver, err := semver.Make(verText)
		if err != nil {
			return semver.Version{}, nil, err
		}

		if latestPublish == nil || ver.GTE(latestRelease) {
			latestRelease = ver
			latestPublish = release
		}
	}
	if latestPublish == nil {
		return semver.Version{}, nil, errors.New("no version found for the templates")
	}
	return latestRelease, latestPublish, nil
}

// downloadReleaseAndUnzip downloads and unzips the release in a directory
func (r *Runner) downloadReleaseAndUnzip(downloadURL string) error {
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("Failed to create HTTP request to %s: %s", downloadURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to download a release file from %s: %s", downloadURL, err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("Failed to download a release file from %s: Not successful status %d", downloadURL, res.StatusCode)
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("Failed to create buffer for zip file: %s", err)
	}

	reader := bytes.NewReader(buf)
	z, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return fmt.Errorf("Failed to uncompress zip file: %s", err)
	}

	// Create the template folder if it doesn't exists
	os.MkdirAll(r.templatesConfig.TemplatesDirectory, os.ModePerm)

	for _, file := range z.File {
		directory, name := filepath.Split(file.Name)
		if name == "" {
			continue
		}
		paths := strings.Split(directory, "/")
		finalPath := strings.Join(paths[1:], "/")

		templateDirectory := path.Join(r.templatesConfig.TemplatesDirectory, finalPath)
		os.MkdirAll(templateDirectory, os.ModePerm)

		f, err := os.Create(path.Join(templateDirectory, name))
		if err != nil {
			return fmt.Errorf("Could not create uncompressed file: %s", err)
		}
		defer f.Close()

		reader, err := file.Open()
		if err != nil {
			return fmt.Errorf("Could not open archive to extract file: %s", err)
		}
		io.Copy(f, reader)
	}
	return nil
}

// isRelative checks if a given path is a relative path
func (r *Runner) isRelative(path string) bool {
	if strings.HasPrefix(path, "/") || strings.Contains(path, ":\\") {
		return false
	}
	return true
}

// resolvePath gets the absolute path to the template by either
// looking in the current directory or checking the nuclei templates directory.
//
// Current directory is given preference over the nuclei-templates directory.
func (r *Runner) resolvePath(templateName string) (string, error) {
	curDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	templatePath := path.Join(curDirectory, templateName)
	if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
		gologger.Infof("Found template in current directory: %s\n", templatePath)
		return templatePath, nil
	}
	if r.templatesConfig != nil {
		templatePath := path.Join(r.templatesConfig.TemplatesDirectory, templateName)
		if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
			gologger.Infof("Found template in nuclei-templates directory: %s\n", templatePath)
			return templatePath, nil
		}
	}
	return "", fmt.Errorf("no such path found: %s", templateName)
}
