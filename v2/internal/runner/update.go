package runner

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blang/semver"
	"github.com/google/go-github/github"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"

	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
)

const (
	userName = "projectdiscovery"
	repoName = "nuclei-templates"
)

const nucleiIgnoreFile = ".nuclei-ignore"

// nucleiConfigFilename is the filename of nuclei configuration file.
const nucleiConfigFilename = ".templates-config.json"

var reVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)

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
	configDir := path.Join(home, "/.config", "/nuclei")
	_ = os.MkdirAll(configDir, os.ModePerm)

	templatesConfigFile := path.Join(configDir, nucleiConfigFilename)
	if _, statErr := os.Stat(templatesConfigFile); !os.IsNotExist(statErr) {
		configuration, readErr := config.ReadConfiguration()
		if err != nil {
			return readErr
		}
		r.templatesConfig = configuration
	}

	ignoreURL := "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/.nuclei-ignore"
	if r.templatesConfig == nil {
		currentConfig := &config.Config{
			TemplatesDirectory: path.Join(home, "nuclei-templates"),
			IgnoreURL:          ignoreURL,
			NucleiVersion:      config.Version,
		}
		if writeErr := config.WriteConfiguration(currentConfig, false, false); writeErr != nil {
			return errors.Wrap(writeErr, "could not write template configuration")
		}
		r.templatesConfig = currentConfig
	}

	if r.options.NoUpdateTemplates {
		return nil
	}
	// Check if last checked for nuclei-ignore is more than 1 hours.
	// and if true, run the check.
	//
	// Also at the same time fetch latest version from github to do outdated nuclei
	// and templates check.
	checkedIgnore := false
	if r.templatesConfig == nil || time.Since(r.templatesConfig.LastCheckedIgnore) > 1*time.Hour || r.options.UpdateTemplates {
		r.fetchLatestVersionsFromGithub()

		if r.templatesConfig != nil && r.templatesConfig.IgnoreURL != "" {
			ignoreURL = r.templatesConfig.IgnoreURL
		}
		gologger.Verbose().Msgf("Downloading config file from %s", ignoreURL)

		checkedIgnore = true
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, ignoreURL, nil)
		if reqErr == nil {
			resp, httpGet := http.DefaultClient.Do(req)
			if httpGet != nil {
				if resp != nil && resp.Body != nil {
					resp.Body.Close()
				}
				gologger.Warning().Msgf("Could not get ignore-file from %s: %s", ignoreURL, err)
			} else {
				data, _ := ioutil.ReadAll(resp.Body)
				resp.Body.Close()

				if len(data) > 0 {
					_ = ioutil.WriteFile(path.Join(configDir, nucleiIgnoreFile), data, 0644)
				}
				if r.templatesConfig != nil {
					err = config.WriteConfiguration(r.templatesConfig, false, true)
					if err != nil {
						gologger.Warning().Msgf("Could not get ignore-file from %s: %s", ignoreURL, err)
					}
				}
			}
		}
		cancel()
	}

	ctx := context.Background()
	if r.templatesConfig.CurrentVersion == "" || (r.options.TemplatesDirectory != "" && r.templatesConfig.TemplatesDirectory != r.options.TemplatesDirectory) {
		gologger.Info().Msgf("nuclei-templates are not installed, installing...\n")

		// Use custom location if user has given a template directory
		r.templatesConfig = &config.Config{
			TemplatesDirectory: path.Join(home, "nuclei-templates"),
		}
		if r.options.TemplatesDirectory != "" && r.options.TemplatesDirectory != path.Join(home, "nuclei-templates") {
			r.templatesConfig.TemplatesDirectory = r.options.TemplatesDirectory
		}

		// Download the repository and also write the revision to a HEAD file.
		version, asset, getErr := r.getLatestReleaseFromGithub()
		if getErr != nil {
			return getErr
		}
		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", version.String(), r.templatesConfig.TemplatesDirectory)

		r.fetchLatestVersionsFromGithub() // also fetch latest versions
		_, err = r.downloadReleaseAndUnzip(ctx, version.String(), asset.GetZipballURL())
		if err != nil {
			return err
		}
		r.templatesConfig.CurrentVersion = version.String()

		err = config.WriteConfiguration(r.templatesConfig, true, checkedIgnore)
		if err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully downloaded nuclei-templates (v%s). GoodLuck!\n", version.String())
		return nil
	}

	// Check if last checked is more than 24 hours and we don't have updateTemplates flag.
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
		return config.WriteConfiguration(r.templatesConfig, false, checkedIgnore)
	}

	if version.GT(oldVersion) {
		gologger.Info().Msgf("Your current nuclei-templates v%s are outdated. Latest is v%s\n", oldVersion, version.String())
		gologger.Info().Msgf("Downloading latest release...")

		if r.options.TemplatesDirectory != "" {
			r.templatesConfig.TemplatesDirectory = r.options.TemplatesDirectory
		}
		r.templatesConfig.CurrentVersion = version.String()

		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", version.String(), r.templatesConfig.TemplatesDirectory)
		r.fetchLatestVersionsFromGithub()
		_, err = r.downloadReleaseAndUnzip(ctx, version.String(), asset.GetZipballURL())
		if err != nil {
			return err
		}
		err = config.WriteConfiguration(r.templatesConfig, true, checkedIgnore)
		if err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully updated nuclei-templates (v%s). GoodLuck!\n", version.String())
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
func (r *Runner) downloadReleaseAndUnzip(ctx context.Context, version, downloadURL string) (*templateUpdateResults, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request to %s: %s", downloadURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download a release file from %s: %s", downloadURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download a release file from %s: Not successful status %d", downloadURL, res.StatusCode)
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create buffer for zip file: %s", err)
	}

	reader := bytes.NewReader(buf)
	z, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress zip file: %s", err)
	}

	// Create the template folder if it doesn't exists
	err = os.MkdirAll(r.templatesConfig.TemplatesDirectory, os.ModePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to create template base folder: %s", err)
	}

	results, err := r.compareAndWriteTemplates(z)
	if err != nil {
		return nil, fmt.Errorf("failed to write templates: %s", err)
	}

	if r.options.Verbose {
		r.printUpdateChangelog(results, version)
	}
	checksumFile := path.Join(r.templatesConfig.TemplatesDirectory, ".checksum")
	err = writeTemplatesChecksum(checksumFile, results.checksums)
	if err != nil {
		return nil, errors.Wrap(err, "could not write checksum")
	}

	// Write the additions to a cached file for new runs.
	additionsFile := path.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
	buffer := &bytes.Buffer{}
	for _, addition := range results.additions {
		buffer.WriteString(addition)
		buffer.WriteString("\n")
	}
	err = ioutil.WriteFile(additionsFile, buffer.Bytes(), os.ModePerm)
	if err != nil {
		return nil, errors.Wrap(err, "could not write new additions file")
	}
	return results, err
}

type templateUpdateResults struct {
	additions     []string
	deletions     []string
	modifications []string
	totalCount    int
	checksums     map[string]string
}

// compareAndWriteTemplates compares and returns the stats of a template
// update operations.
func (r *Runner) compareAndWriteTemplates(z *zip.Reader) (*templateUpdateResults, error) {
	results := &templateUpdateResults{
		checksums: make(map[string]string),
	}

	// We use file-checksums that are md5 hashes to store the list of files->hashes
	// that have been downloaded previously.
	// If the path isn't found in new update after being read from the previous checksum,
	// it is removed. This allows us fine-grained control over the download process
	// as well as solves a long problem with nuclei-template updates.
	checksumFile := path.Join(r.templatesConfig.TemplatesDirectory, ".checksum")
	previousChecksum, _ := readPreviousTemplatesChecksum(checksumFile)
	for _, file := range z.File {
		directory, name := filepath.Split(file.Name)
		if name == "" {
			continue
		}
		paths := strings.Split(directory, "/")
		finalPath := strings.Join(paths[1:], "/")

		if strings.HasPrefix(name, ".") || strings.HasPrefix(finalPath, ".") || strings.EqualFold(name, "README.md") {
			continue
		}
		results.totalCount++
		templateDirectory := path.Join(r.templatesConfig.TemplatesDirectory, finalPath)
		err := os.MkdirAll(templateDirectory, os.ModePerm)
		if err != nil {
			return nil, fmt.Errorf("failed to create template folder %s : %s", templateDirectory, err)
		}

		templatePath := path.Join(templateDirectory, name)

		isAddition := false
		if _, statErr := os.Stat(templatePath); os.IsNotExist(statErr) {
			isAddition = true
		}
		f, err := os.OpenFile(templatePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("could not create uncompressed file: %s", err)
		}

		reader, err := file.Open()
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("could not open archive to extract file: %s", err)
		}
		hasher := md5.New()

		// Save file and also read into hasher for md5
		_, err = io.Copy(f, io.TeeReader(reader, hasher))
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("could not write template file: %s", err)
		}
		f.Close()

		oldChecksum, checksumOK := previousChecksum[templatePath]

		checksum := hex.EncodeToString(hasher.Sum(nil))
		if isAddition {
			results.additions = append(results.additions, path.Join(finalPath, name))
		} else if checksumOK && oldChecksum[0] != checksum {
			results.modifications = append(results.modifications, path.Join(finalPath, name))
		}
		results.checksums[templatePath] = checksum
	}

	// If we don't find a previous file in new download and it hasn't been
	// changed on the disk, delete it.
	for k, v := range previousChecksum {
		_, ok := results.checksums[k]
		if !ok && v[0] == v[1] {
			os.Remove(k)
			results.deletions = append(results.deletions, strings.TrimPrefix(strings.TrimPrefix(k, r.templatesConfig.TemplatesDirectory), "/"))
		}
	}
	return results, nil
}

// readPreviousTemplatesChecksum reads the previous checksum file from the disk.
//
// It reads two checksums, the first checksum is what we expect and the second is
// the actual checksum of the file on disk currently.
func readPreviousTemplatesChecksum(file string) (map[string][2]string, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
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
			return nil, err
		}

		hasher := md5.New()
		if _, err := io.Copy(hasher, f); err != nil {
			return nil, err
		}
		f.Close()

		values[1] = hex.EncodeToString(hasher.Sum(nil))
		checksum[parts[0]] = values
	}
	return checksum, nil
}

// writeTemplatesChecksum writes the nuclei-templates checksum data to disk.
func writeTemplatesChecksum(file string, checksum map[string]string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	builder := &strings.Builder{}
	for k, v := range checksum {
		builder.WriteString(k)
		builder.WriteString(",")
		builder.WriteString(v)
		builder.WriteString("\n")

		if _, checksumErr := f.WriteString(builder.String()); checksumErr != nil {
			return err
		}
		builder.Reset()
	}
	return nil
}

func (r *Runner) printUpdateChangelog(results *templateUpdateResults, version string) {
	if len(results.additions) > 0 && r.options.Verbose {
		gologger.Print().Msgf("\nNewly added templates: \n\n")

		for _, addition := range results.additions {
			gologger.Print().Msgf("%s", addition)
		}
	}

	gologger.Print().Msgf("\nNuclei Templates v%s Changelog\n", version)
	data := [][]string{
		{strconv.Itoa(results.totalCount), strconv.Itoa(len(results.additions)), strconv.Itoa(len(results.deletions))},
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Total", "Added", "Removed"})
	for _, v := range data {
		table.Append(v)
	}
	table.Render()
}

// fetchLatestVersionsFromGithub fetches latest versions of nuclei repos from github
func (r *Runner) fetchLatestVersionsFromGithub() {
	nucleiLatest, err := r.githubFetchLatestTagRepo("projectdiscovery/nuclei")
	if err != nil {
		gologger.Warning().Msgf("Could not fetch latest nuclei release: %s", err)
	}
	templatesLatest, err := r.githubFetchLatestTagRepo("projectdiscovery/nuclei-templates")
	if err != nil {
		gologger.Warning().Msgf("Could not fetch latest nuclei-templates release: %s", err)
	}
	if r.templatesConfig != nil {
		r.templatesConfig.NucleiLatestVersion = nucleiLatest
		r.templatesConfig.NucleiTemplatesLatestVersion = templatesLatest
	}
}

type githubTagData struct {
	Name string
}

// githubFetchLatestTagRepo fetches latest tag from github
// This function was half written by github copilot AI :D.
func (r *Runner) githubFetchLatestTagRepo(repo string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://api.github.com/repos/%s/tags", repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var tags []githubTagData
	err = json.Unmarshal(body, &tags)
	if err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", fmt.Errorf("no tags found for %s", repo)
	}
	return strings.TrimPrefix(tags[0].Name, "v"), nil
}

// updateNucleiVersionToLatest implements nuclei auto-updation using Github Releases.
func updateNucleiVersionToLatest(verbose bool) error {
	if verbose {
		log.SetLevel(log.DebugLevel)
	}
	var command string
	switch runtime.GOOS {
	case "windows":
		command = "nuclei.exe"
	default:
		command = "nuclei"
	}
	m := &update.Manager{
		Command: command,
		Store: &githubUpdateStore.Store{
			Owner:   "projectdiscovery",
			Repo:    "nuclei",
			Version: config.Version,
		},
	}
	releases, err := m.LatestReleases()
	if err != nil {
		return errors.Wrap(err, "could not fetch latest release")
	}
	if len(releases) == 0 {
		gologger.Info().Msgf("No new updates found for nuclei engine!")
		return nil
	}

	latest := releases[0]
	var currentOS string
	switch runtime.GOOS {
	case "darwin":
		currentOS = "macOS"
	default:
		currentOS = runtime.GOOS
	}
	final := latest.FindZip(currentOS, runtime.GOARCH)
	if final == nil {
		return fmt.Errorf("no compatible binary found for %s/%s", currentOS, runtime.GOARCH)
	}
	tarball, err := final.DownloadProxy(progress.Reader)
	if err != nil {
		return errors.Wrap(err, "could not download latest release")
	}
	if err := m.Install(tarball); err != nil {
		return errors.Wrap(err, "could not install latest release")
	}
	gologger.Info().Msgf("Successfully updated to Nuclei %s\n", latest.Version)
	return nil
}
