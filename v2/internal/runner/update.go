package runner

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver"
	"github.com/google/go-github/v32/github"
	"github.com/olekukonko/tablewriter"
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
			gologger.Warning().Msgf("nuclei-templates are not installed, use update-templates flag.\n")
			return nil
		}

		// Use custom location if user has given a template directory
		r.templatesConfig = &nucleiConfig{TemplatesDirectory: path.Join(home, "nuclei-templates")}
		if r.options.TemplatesDirectory != "" && r.options.TemplatesDirectory != path.Join(home, "nuclei-templates") {
			r.templatesConfig.TemplatesDirectory = r.options.TemplatesDirectory
		}

		// Download the repository and also write the revision to a HEAD file.
		version, asset, getErr := r.getLatestReleaseFromGithub()
		if getErr != nil {
			return getErr
		}
		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", version.String(), r.templatesConfig.TemplatesDirectory)

		err = r.downloadReleaseAndUnzip(ctx, version.String(), asset.GetZipballURL())
		if err != nil {
			return err
		}
		r.templatesConfig.CurrentVersion = version.String()

		err = r.writeConfiguration(r.templatesConfig)
		if err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully downloaded nuclei-templates (v%s). Enjoy!\n", version.String())
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
		gologger.Info().Msgf("Your nuclei-templates are up to date: v%s\n", oldVersion.String())
		return r.writeConfiguration(r.templatesConfig)
	}

	if version.GT(oldVersion) {
		if !r.options.UpdateTemplates {
			gologger.Warning().Msgf("Your current nuclei-templates v%s are outdated. Latest is v%s\n", oldVersion, version.String())
			return r.writeConfiguration(r.templatesConfig)
		}

		if r.options.TemplatesDirectory != "" {
			r.templatesConfig.TemplatesDirectory = r.options.TemplatesDirectory
		}
		r.templatesConfig.CurrentVersion = version.String()

		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", version.String(), r.templatesConfig.TemplatesDirectory)
		err = r.downloadReleaseAndUnzip(ctx, version.String(), asset.GetZipballURL())
		if err != nil {
			return err
		}

		err = r.writeConfiguration(r.templatesConfig)
		if err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully updated nuclei-templates (v%s). Enjoy!\n", version.String())
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
func (r *Runner) downloadReleaseAndUnzip(ctx context.Context, version, downloadURL string) error {
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

	totalCount := 0
	additions, deletions, modifications := []string{}, []string{}, []string{}
	// We use file-checksums that are md5 hashes to store the list of files->hashes
	// that have been downloaded previously.
	// If the path isn't found in new update after being read from the previous checksum,
	// it is removed. This allows us fine-grained control over the download process
	// as well as solves a long problem with nuclei-template updates.
	checksumFile := path.Join(r.templatesConfig.TemplatesDirectory, ".checksum")
	previousChecksum := readPreviousTemplatesChecksum(checksumFile)
	checksums := make(map[string]string)
	for _, file := range z.File {
		directory, name := filepath.Split(file.Name)
		if name == "" {
			continue
		}
		paths := strings.Split(directory, "/")
		finalPath := strings.Join(paths[1:], "/")

		if (!strings.EqualFold(name, ".nuclei-ignore") && strings.HasPrefix(name, ".")) || strings.HasPrefix(finalPath, ".") || strings.EqualFold(name, "README.md") {
			continue
		}
		totalCount++
		templateDirectory := path.Join(r.templatesConfig.TemplatesDirectory, finalPath)
		err = os.MkdirAll(templateDirectory, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create template folder %s : %s", templateDirectory, err)
		}

		templatePath := path.Join(templateDirectory, name)

		isAddition := false
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			isAddition = true
		}
		f, err := os.OpenFile(templatePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
		if err != nil {
			f.Close()
			return fmt.Errorf("could not create uncompressed file: %s", err)
		}

		reader, err := file.Open()
		if err != nil {
			f.Close()
			return fmt.Errorf("could not open archive to extract file: %s", err)
		}
		hasher := md5.New()

		// Save file and also read into hasher for md5
		_, err = io.Copy(f, io.TeeReader(reader, hasher))
		if err != nil {
			f.Close()
			return fmt.Errorf("could not write template file: %s", err)
		}
		f.Close()

		if isAddition {
			additions = append(additions, path.Join(finalPath, name))
		} else {
			modifications = append(modifications, path.Join(finalPath, name))
		}
		checksums[templatePath] = hex.EncodeToString(hasher.Sum(nil))
	}

	// If we don't find a previous file in new download and it hasn't been
	// changed on the disk, delete it.
	if previousChecksum != nil {
		for k, v := range previousChecksum {
			_, ok := checksums[k]
			if !ok && v[0] == v[1] {
				os.Remove(k)
				deletions = append(deletions, strings.TrimPrefix(strings.TrimPrefix(k, r.templatesConfig.TemplatesDirectory), "/"))
			}
		}
	}
	r.printUpdateChangelog(additions, modifications, deletions, version, totalCount)
	return writeTemplatesChecksum(checksumFile, checksums)
}

// readPreviousTemplatesChecksum reads the previous checksum file from the disk.
//
// It reads two checksums, the first checksum is what we expect and the second is
// the actual checksum of the file on disk currently.
func readPreviousTemplatesChecksum(file string) map[string][2]string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)

	checksum := make(map[string][2]string)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		parts := strings.Split(text, ",")
		if len(parts) < 2 {
			continue
		}
		values := [2]string{parts[1]}

		f, err := os.Open(parts[0])
		if err != nil {
			continue
		}

		hasher := md5.New()
		if _, err := io.Copy(hasher, f); err != nil {
			f.Close()
			continue
		}
		f.Close()

		values[1] = hex.EncodeToString(hasher.Sum(nil))
		checksum[parts[0]] = values
	}
	return checksum
}

// writeTemplatesChecksum writes the nuclei-templates checksum data to disk.
func writeTemplatesChecksum(file string, checksum map[string]string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	for k, v := range checksum {
		f.WriteString(k)
		f.WriteString(",")
		f.WriteString(v)
		f.WriteString("\n")
	}
	return nil
}

func (r *Runner) printUpdateChangelog(additions, modifications, deletions []string, version string, totalCount int) {
	if len(additions) > 0 {
		gologger.Print().Msgf("\nNew additions: \n\n")

		for _, addition := range additions {
			gologger.Print().Msgf("%s", addition)
		}
	}
	if len(modifications) > 0 {
		gologger.Print().Msgf("\nModifications: \n\n")

		for _, modification := range modifications {
			gologger.Print().Msgf("%s", modification)
		}
	}
	if len(deletions) > 0 {
		gologger.Print().Msgf("\nDeletions: \n\n")

		for _, deletion := range deletions {
			gologger.Print().Msgf("%s", deletion)
		}
	}

	gologger.Print().Msgf("\nNuclei Templates v%s Changelog\n", version)
	data := [][]string{
		{strconv.Itoa(totalCount), strconv.Itoa(len(additions)), strconv.Itoa(len(modifications)), strconv.Itoa(len(deletions))},
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Total", "New", "Modifications", "Deletions"})
	for _, v := range data {
		table.Append(v)
	}
	table.Render()
}
