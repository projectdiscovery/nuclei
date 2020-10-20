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
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/google/go-github/v32/github"
	"github.com/projectdiscovery/gologger"
)

const (
	userName = "projectdiscovery"
	repoName = "nuclei-templates"
)

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
	if _, statErr := os.Stat(templatesConfigFile); !os.IsNotExist(statErr) {
		config, readErr := readConfiguration()
		if err != nil {
			return readErr
		}
		r.templatesConfig = config
	}

	ctx := context.Background()

	if r.templatesConfig == nil || (r.options.TemplatesDirectory != "" && r.templatesConfig.TemplatesDirectory != r.options.TemplatesDirectory) {
		if !r.options.UpdateTemplates {
			gologger.Labelf("nuclei-templates are not installed, use update-templates flag.\n")
			return nil
		}

		// Use custom location if user has given a template directory
		if r.options.TemplatesDirectory != "" {
			home = r.options.TemplatesDirectory
		}

		r.templatesConfig = &nucleiConfig{TemplatesDirectory: path.Join(home, "nuclei-templates")}

		// Download the repository and also write the revision to a HEAD file.
		version, asset, getErr := r.getLatestReleaseFromGithub()
		if getErr != nil {
			return getErr
		}

		gologger.Verbosef("Downloading nuclei-templates (v%s) to %s\n", "update-templates", version.String(), r.templatesConfig.TemplatesDirectory)

		err = r.downloadReleaseAndUnzip(ctx, asset.GetZipballURL())
		if err != nil {
			return err
		}

		r.templatesConfig.CurrentVersion = version.String()

		err = r.writeConfiguration(r.templatesConfig)
		if err != nil {
			return err
		}

		gologger.Infof("Successfully downloaded nuclei-templates (v%s). Enjoy!\n", version.String())

		return nil
	}

	// Check if last checked is more than 24 hours.
	// If not, return since we don't want to do anything now.
	if time.Since(r.templatesConfig.LastChecked) < 24*time.Hour && !r.options.UpdateTemplates {
		return nil
	}

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
		gologger.Infof("Your nuclei-templates are up to date: v%s\n", oldVersion.String())
		return r.writeConfiguration(r.templatesConfig)
	}

	if version.GT(oldVersion) {
		if !r.options.UpdateTemplates {
			gologger.Labelf("Your current nuclei-templates v%s are outdated. Latest is v%s\n", oldVersion, version.String())
			return r.writeConfiguration(r.templatesConfig)
		}

		if r.options.TemplatesDirectory != "" {
			home = r.options.TemplatesDirectory
			r.templatesConfig.TemplatesDirectory = path.Join(home, "nuclei-templates")
		}

		r.templatesConfig.CurrentVersion = version.String()

		gologger.Verbosef("Downloading nuclei-templates (v%s) to %s\n", "update-templates", version.String(), r.templatesConfig.TemplatesDirectory)

		err = r.downloadReleaseAndUnzip(ctx, asset.GetZipballURL())
		if err != nil {
			return err
		}

		err = r.writeConfiguration(r.templatesConfig)
		if err != nil {
			return err
		}

		gologger.Infof("Successfully updated nuclei-templates (v%s). Enjoy!\n", version.String())
	}

	return nil
}

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
func (r *Runner) downloadReleaseAndUnzip(ctx context.Context, downloadURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request to %s: %s", downloadURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download a release file from %s: %s", downloadURL, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download a release file from %s: Not successful status %d", downloadURL, res.StatusCode)
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to create buffer for zip file: %s", err)
	}

	reader := bytes.NewReader(buf)
	z, err := zip.NewReader(reader, reader.Size())

	if err != nil {
		return fmt.Errorf("failed to uncompress zip file: %s", err)
	}

	// Create the template folder if it doesn't exists
	err = os.MkdirAll(r.templatesConfig.TemplatesDirectory, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to create template base folder: %s", err)
	}

	for _, file := range z.File {
		directory, name := filepath.Split(file.Name)
		if name == "" {
			continue
		}

		paths := strings.Split(directory, "/")
		finalPath := strings.Join(paths[1:], "/")

		templateDirectory := path.Join(r.templatesConfig.TemplatesDirectory, finalPath)
		err = os.MkdirAll(templateDirectory, os.ModePerm)

		if err != nil {
			return fmt.Errorf("failed to create template folder %s : %s", templateDirectory, err)
		}

		f, err := os.OpenFile(path.Join(templateDirectory, name), os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
		if err != nil {
			f.Close()
			return fmt.Errorf("could not create uncompressed file: %s", err)
		}

		reader, err := file.Open()
		if err != nil {
			f.Close()
			return fmt.Errorf("could not open archive to extract file: %s", err)
		}

		_, err = io.Copy(f, reader)
		if err != nil {
			f.Close()
			return fmt.Errorf("could not write template file: %s", err)
		}

		f.Close()
	}

	return nil
}
