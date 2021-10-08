package runner

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blang/semver"
	"github.com/google/go-github/github"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei-updatecheck-api/client"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"

	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	githubUpdateStore "github.com/tj/go-update/stores/github"
)

const (
	userName             = "projectdiscovery"
	repoName             = "nuclei-templates"
	nucleiIgnoreFile     = ".nuclei-ignore"
	nucleiConfigFilename = ".templates-config.json"
)

var reVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)

// updateTemplates checks if the default list of nuclei-templates
// exist in the user's home directory, if not the latest revision
// is downloaded from GitHub.
//
// If the path exists but does not contain the latest version of public templates,
// the new version is downloaded from GitHub to the templates' directory, overwriting the old content.
func (r *Runner) updateTemplates() error { // TODO this method does more than just update templates. Should be refactored.
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configDir := filepath.Join(home, ".config", "nuclei")
	_ = os.MkdirAll(configDir, os.ModePerm)

	if err := r.readInternalConfigurationFile(home, configDir); err != nil {
		return errors.Wrap(err, "could not read configuration file")
	}

	// If the config doesn't exist, create it now.
	if r.templatesConfig == nil {
		currentConfig := &config.Config{
			TemplatesDirectory: filepath.Join(home, "nuclei-templates"),
			NucleiVersion:      config.Version,
		}
		if writeErr := config.WriteConfiguration(currentConfig); writeErr != nil {
			return errors.Wrap(writeErr, "could not write template configuration")
		}
		r.templatesConfig = currentConfig
	}

	if r.options.NoUpdateTemplates && !r.options.UpdateTemplates {
		return nil
	}

	client.InitNucleiVersion(config.Version)
	r.fetchLatestVersionsFromGithub(configDir) // also fetch the latest versions

	ctx := context.Background()

	var noTemplatesFound bool
	if _, err := os.Stat(r.templatesConfig.TemplatesDirectory); os.IsNotExist(err) {
		noTemplatesFound = true
	}

	if r.templatesConfig.TemplateVersion == "" || (r.options.TemplatesDirectory != "" && r.templatesConfig.TemplatesDirectory != r.options.TemplatesDirectory) || noTemplatesFound {
		gologger.Info().Msgf("nuclei-templates are not installed, installing...\n")

		// Use the custom location if the user has given a template directory
		r.templatesConfig = &config.Config{
			TemplatesDirectory: filepath.Join(home, "nuclei-templates"),
		}
		if r.options.TemplatesDirectory != "" && r.options.TemplatesDirectory != filepath.Join(home, "nuclei-templates") {
			r.templatesConfig.TemplatesDirectory, _ = filepath.Abs(r.options.TemplatesDirectory)
		}
		r.fetchLatestVersionsFromGithub(configDir) // also fetch the latest versions

		version, err := semver.Parse(r.templatesConfig.NucleiTemplatesLatestVersion)
		if err != nil {
			return err
		}

		// Download the repository and write the revision to a HEAD file.
		asset, getErr := r.getLatestReleaseFromGithub(r.templatesConfig.NucleiTemplatesLatestVersion)
		if getErr != nil {
			return getErr
		}
		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", version.String(), r.templatesConfig.TemplatesDirectory)

		if _, err := r.downloadReleaseAndUnzip(ctx, version.String(), asset.GetZipballURL()); err != nil {
			return err
		}
		r.templatesConfig.TemplateVersion = version.String()

		if err := config.WriteConfiguration(r.templatesConfig); err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully downloaded nuclei-templates (v%s). GoodLuck!\n", version.String())
		return nil
	}

	latestVersion, currentVersion, err := getVersions(r)
	if err != nil {
		return err
	}

	if latestVersion.EQ(currentVersion) {
		if r.options.UpdateTemplates {
			gologger.Info().Msgf("No new updates found for nuclei templates")
		}
		return config.WriteConfiguration(r.templatesConfig)
	}

	if err := updateTemplates(latestVersion, currentVersion, r, ctx); err != nil {
		return err
	}
	return nil
}

func updateTemplates(latestVersion semver.Version, currentVersion semver.Version, runner *Runner, ctx context.Context) error {
	if latestVersion.GT(currentVersion) {
		gologger.Info().Msgf("Your current nuclei-templates v%s are outdated. Latest is v%s\n", currentVersion, latestVersion.String())
		gologger.Info().Msgf("Downloading latest release...")

		if runner.options.TemplatesDirectory != "" {
			runner.templatesConfig.TemplatesDirectory = runner.options.TemplatesDirectory
		}
		runner.templatesConfig.TemplateVersion = latestVersion.String()

		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", latestVersion.String(), runner.templatesConfig.TemplatesDirectory)

		asset, err := runner.getLatestReleaseFromGithub(runner.templatesConfig.NucleiTemplatesLatestVersion)
		if err != nil {
			return err
		}
		if _, err := runner.downloadReleaseAndUnzip(ctx, latestVersion.String(), asset.GetZipballURL()); err != nil {
			return err
		}
		if err := config.WriteConfiguration(runner.templatesConfig); err != nil {
			return err
		}
		gologger.Info().Msgf("Successfully updated nuclei-templates (v%s). GoodLuck!\n", latestVersion.String())
	}
	return nil
}

func getVersions(runner *Runner) (semver.Version, semver.Version, error) {
	// Get the configuration currently on disk.
	verText := runner.templatesConfig.TemplateVersion
	indices := reVersion.FindStringIndex(verText)
	if indices == nil {
		return semver.Version{}, semver.Version{}, fmt.Errorf("invalid release found with tag %s", verText)
	}
	if indices[0] > 0 {
		verText = verText[indices[0]:]
	}

	currentVersion, err := semver.Make(verText)
	if err != nil {
		return semver.Version{}, semver.Version{}, err
	}

	latestVersion, err := semver.Parse(runner.templatesConfig.NucleiTemplatesLatestVersion)
	if err != nil {
		return semver.Version{}, semver.Version{}, err
	}
	return latestVersion, currentVersion, nil
}

// readInternalConfigurationFile reads the internal configuration file for nuclei
func (r *Runner) readInternalConfigurationFile(home, configDir string) error {
	templatesConfigFile := filepath.Join(configDir, nucleiConfigFilename)
	if _, statErr := os.Stat(templatesConfigFile); !os.IsNotExist(statErr) {
		configuration, readErr := config.ReadConfiguration()
		if readErr != nil {
			return readErr
		}
		r.templatesConfig = configuration

		if configuration.TemplatesDirectory != "" && configuration.TemplatesDirectory != filepath.Join(home, "nuclei-templates") {
			r.options.TemplatesDirectory = configuration.TemplatesDirectory
		}
	}
	return nil
}

// checkNucleiIgnoreFileUpdates checks .nuclei-ignore file for updates from GitHub
func (r *Runner) checkNucleiIgnoreFileUpdates(configDir string) bool {
	data, err := client.GetLatestIgnoreFile()
	if err != nil {
		return false
	}
	if len(data) > 0 {
		_ = ioutil.WriteFile(filepath.Join(configDir, nucleiIgnoreFile), data, 0644)
	}
	if r.templatesConfig != nil {
		if err := config.WriteConfiguration(r.templatesConfig); err != nil {
			gologger.Warning().Msgf("Could not get ignore-file from server: %s", err)
		}
	}
	return true
}

// getLatestReleaseFromGithub returns the latest release from GitHub
func (r *Runner) getLatestReleaseFromGithub(latestTag string) (*github.RepositoryRelease, error) {
	gitHubClient := github.NewClient(nil)

	release, _, err := gitHubClient.Repositories.GetReleaseByTag(context.Background(), userName, repoName, "v"+latestTag)
	if err != nil {
		return nil, err
	}
	if release == nil {
		return nil, errors.New("no version found for the templates")
	}
	return release, nil
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
	zipReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress zip file: %s", err)
	}

	// Create the template folder if it doesn't exist
	if err := os.MkdirAll(r.templatesConfig.TemplatesDirectory, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create template base folder: %s", err)
	}

	results, err := r.compareAndWriteTemplates(zipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to write templates: %s", err)
	}

	if r.options.Verbose {
		r.printUpdateChangelog(results, version)
	}
	checksumFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".checksum")
	if err := writeTemplatesChecksum(checksumFile, results.checksums); err != nil {
		return nil, errors.Wrap(err, "could not write checksum")
	}

	// Write the additions to a cached file for new runs.
	additionsFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".new-additions")
	buffer := &bytes.Buffer{}
	for _, addition := range results.additions {
		buffer.WriteString(addition)
		buffer.WriteString("\n")
	}

	if err := ioutil.WriteFile(additionsFile, buffer.Bytes(), os.ModePerm); err != nil {
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

// compareAndWriteTemplates compares and returns the stats of a template update operations.
func (r *Runner) compareAndWriteTemplates(zipReader *zip.Reader) (*templateUpdateResults, error) {
	results := &templateUpdateResults{
		checksums: make(map[string]string),
	}

	// We use file-checksums that are md5 hashes to store the list of files->hashes
	// that have been downloaded previously.
	// If the path isn't found in new update after being read from the previous checksum,
	// it is removed. This allows us fine-grained control over the download process
	// as well as solves a long problem with nuclei-template updates.
	checksumFile := filepath.Join(r.templatesConfig.TemplatesDirectory, ".checksum")
	templateChecksumsMap, _ := createTemplateChecksumsMap(checksumFile)
	for _, zipTemplateFile := range zipReader.File {
		directory, name := filepath.Split(zipTemplateFile.Name)
		if name == "" {
			continue
		}
		paths := strings.Split(directory, string(os.PathSeparator))
		finalPath := filepath.Join(paths[1:]...)

		if strings.HasPrefix(name, ".") || strings.HasPrefix(finalPath, ".") || strings.EqualFold(name, "README.md") {
			continue
		}
		results.totalCount++
		templateDirectory := filepath.Join(r.templatesConfig.TemplatesDirectory, finalPath)
		if err := os.MkdirAll(templateDirectory, os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create template folder %s : %s", templateDirectory, err)
		}

		templatePath := filepath.Join(templateDirectory, name)

		isAddition := false
		if _, statErr := os.Stat(templatePath); os.IsNotExist(statErr) {
			isAddition = true
		}
		templateFile, err := os.OpenFile(templatePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
		if err != nil {
			templateFile.Close()
			return nil, fmt.Errorf("could not create uncompressed file: %s", err)
		}

		zipTemplateFileReader, err := zipTemplateFile.Open()
		if err != nil {
			templateFile.Close()
			return nil, fmt.Errorf("could not open archive to extract file: %s", err)
		}
		hasher := md5.New()

		// Save file and also read into hasher for md5
		if _, err := io.Copy(templateFile, io.TeeReader(zipTemplateFileReader, hasher)); err != nil {
			templateFile.Close()
			return nil, fmt.Errorf("could not write template file: %s", err)
		}
		templateFile.Close()

		oldChecksum, checksumOK := templateChecksumsMap[templatePath]

		checksum := hex.EncodeToString(hasher.Sum(nil))
		if isAddition {
			results.additions = append(results.additions, filepath.Join(finalPath, name))
		} else if checksumOK && oldChecksum[0] != checksum {
			results.modifications = append(results.modifications, filepath.Join(finalPath, name))
		}
		results.checksums[templatePath] = checksum
	}

	// If we don't find the previous file in the newly downloaded list,
	// and it hasn't been changed on the disk, delete it.
	for templatePath, templateChecksums := range templateChecksumsMap {
		_, ok := results.checksums[templatePath]
		if !ok && templateChecksums[0] == templateChecksums[1] {
			_ = os.Remove(templatePath)
			results.deletions = append(results.deletions, strings.TrimPrefix(strings.TrimPrefix(templatePath, r.templatesConfig.TemplatesDirectory), string(os.PathSeparator)))
		}
	}
	return results, nil
}

// createTemplateChecksumsMap reads the previous checksum file from the disk.
// Creates a map of template paths and their previous and currently calculated checksums as values.
func createTemplateChecksumsMap(checksumsFilePath string) (map[string][2]string, error) {
	checksumFile, err := os.Open(checksumsFilePath)
	if err != nil {
		return nil, err
	}
	defer checksumFile.Close()
	scanner := bufio.NewScanner(checksumFile)

	templatePathChecksumsMap := make(map[string][2]string)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}

		parts := strings.Split(text, ",")
		if len(parts) < 2 {
			continue
		}
		templatePath := parts[0]
		expectedTemplateChecksum := parts[1]

		templateFile, err := os.Open(templatePath)
		if err != nil {
			return nil, err
		}

		hasher := md5.New()
		if _, err := io.Copy(hasher, templateFile); err != nil {
			return nil, err
		}
		templateFile.Close()

		values := [2]string{expectedTemplateChecksum}
		values[1] = hex.EncodeToString(hasher.Sum(nil))
		templatePathChecksumsMap[templatePath] = values
	}
	return templatePathChecksumsMap, nil
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

// fetchLatestVersionsFromGithub fetches the latest versions of nuclei repos from GitHub
//
// This fetches the latest nuclei/templates/ignore from https://version-check.nuclei.sh/versions
// If you want to disable this automatic update check, use -nut flag.
func (r *Runner) fetchLatestVersionsFromGithub(configDir string) {
	versions, err := client.GetLatestNucleiTemplatesVersion()
	if err != nil {
		gologger.Warning().Msgf("Could not fetch latest releases: %s", err)
		return
	}
	if r.templatesConfig != nil {
		r.templatesConfig.NucleiLatestVersion = versions.Nuclei
		r.templatesConfig.NucleiTemplatesLatestVersion = versions.Templates

		// If the fetch has resulted in new version of ignore file, update.
		if r.templatesConfig.NucleiIgnoreHash == "" || r.templatesConfig.NucleiIgnoreHash != versions.IgnoreHash {
			r.templatesConfig.NucleiIgnoreHash = versions.IgnoreHash
			r.checkNucleiIgnoreFileUpdates(configDir)
		}
	}
}

// updateNucleiVersionToLatest implements nuclei auto-update using GitHub Releases.
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
