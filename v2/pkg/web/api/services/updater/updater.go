package updater

import (
	"archive/zip"
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
	"strings"
	"sync"
	"time"

	"github.com/blang/semver"
	"github.com/google/go-github/github"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei-updatecheck-api/client"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db"
	"github.com/projectdiscovery/nuclei/v2/pkg/web/db/dbsql"
)

var (
	ignoreFile       []byte
	ignoreHash       string
	currentTemplates semver.Version
	mutex            *sync.RWMutex
)

// GetIgnoreFile returns the current ignore file contents
func GetIgnoreFile() []byte {
	mutex.RLock()
	data := ignoreFile
	mutex.RUnlock()
	return data
}

func init() {
	mutex = &sync.RWMutex{}
}

// RunUpdateCheckers runs an update checker goroutine that keeps templates
// upto date from the nuclei-templates repository when used as a webservice.
func RunUpdateChecker(db *db.Database) context.CancelFunc {
	client.InitNucleiVersion(config.Version)

	ctx, cancel := context.WithCancel(context.Background())
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		// First startup requirements
		if version, err := UpdateTemplates(db, semver.Version{}); err == nil {
			mutex.Lock()
			currentTemplates = version
			mutex.Unlock()
		} else {
			gologger.Error().Msgf("Could not update template: %s\n", err)
		}

		for {
			select {
			case <-ticker.C:
				mutex.RLock()
				currentVersion := currentTemplates
				mutex.RUnlock()

				if version, err := UpdateTemplates(db, currentVersion); err != nil {
					gologger.Error().Msgf("Could not update templates: %s\n", err)
				} else {
					mutex.Lock()
					currentTemplates = version
					mutex.Unlock()
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
	return cancel
}

const (
	userName = "projectdiscovery"
	repoName = "nuclei-templates"
)

// UpdateTemplates takes a db and writes templates to db.
func UpdateTemplates(db *db.Database, lastVersion semver.Version) (semver.Version, error) {
	versions, err := client.GetLatestNucleiTemplatesVersion()
	if err != nil {
		return semver.Version{}, err
	}

	mutex.RLock()
	currentIgnoreHash := ignoreHash
	mutex.RUnlock()

	if versions.IgnoreHash != currentIgnoreHash {
		data, err := client.GetLatestIgnoreFile()
		if err != nil {
			return semver.Version{}, err
		}

		mutex.Lock()
		ignoreFile = data
		ignoreHash = versions.IgnoreHash
		mutex.Unlock()
	}
	ctx := context.Background()

	parsed, err := semver.Parse(versions.Templates)
	if err != nil {
		return semver.Version{}, err
	}
	row, _ := db.Queries().GetTemplatesByFolderOne(context.Background(), repoName)

	notInstalledTemplates := row.Hash == ""

	if notInstalledTemplates {
		// Download the repository and write the revision to a HEAD file.
		asset, getErr := getLatestReleaseFromGithub(versions.Templates)
		if getErr != nil {
			return semver.Version{}, getErr
		}
		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to db\n", versions.Templates)

		if _, err := downloadReleaseAndUnzip(ctx, db, versions.Templates, asset.GetZipballURL()); err != nil {
			return semver.Version{}, err
		}
		gologger.Info().Msgf("Successfully downloaded nuclei-templates (v%s). GoodLuck!\n", versions.Templates)
		return parsed, nil
	}

	if parsed.EQ(currentTemplates) {
		gologger.Info().Msgf("No new updates found for nuclei templates")
		return currentTemplates, nil
	}

	if parsed.GT(currentTemplates) {
		gologger.Info().Msgf("Your current nuclei-templates v%s are outdated. Latest is v%s\n", currentTemplates.String(), parsed.String())
		gologger.Info().Msgf("Downloading latest release...")

		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to storage\n", parsed.String())

		asset, err := getLatestReleaseFromGithub(parsed.String())
		if err != nil {
			return currentTemplates, err
		}
		if _, err := downloadReleaseAndUnzip(ctx, db, parsed.String(), asset.GetZipballURL()); err != nil {
			return currentTemplates, err
		}
		gologger.Info().Msgf("Successfully updated nuclei-templates (v%s). GoodLuck!\n", parsed.String())
	}
	return parsed, nil
}

// getLatestReleaseFromGithub returns the latest release from GitHub
func getLatestReleaseFromGithub(latestTag string) (*github.RepositoryRelease, error) {
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
func downloadReleaseAndUnzip(ctx context.Context, db *db.Database, version, downloadURL string) (*templateUpdateResults, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request to %s: %w", downloadURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download a release file from %s: %w", downloadURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download a release file from %s: Not successful status %d", downloadURL, res.StatusCode)
	}

	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create buffer for zip file: %w", err)
	}

	reader := bytes.NewReader(buf)
	zipReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress zip file: %w", err)
	}

	results, err := compareAndWriteTemplates(zipReader, db)
	if err != nil {
		return nil, fmt.Errorf("failed to write templates: %w", err)
	}
	return results, err
}

type templateUpdateResults struct {
	additions     []string
	deletions     []string
	modifications []string
	totalCount    int
}

// compareAndWriteTemplates compares and returns the stats of a template update operations.
func compareAndWriteTemplates(zipReader *zip.Reader, db *db.Database) (*templateUpdateResults, error) {
	templates, err := db.Queries().GetTemplatesByFolder(context.Background(), repoName)
	if err != nil {
		return nil, errors.Wrap(err, "could not get templates list")
	}

	templateChecksumsMap := make(map[string]string, len(templates))
	for _, template := range templates {
		templateChecksumsMap[template.Path] = template.Hash
	}

	results := &templateUpdateResults{}
	// We use file-checksums that are md5 hashes to store the list of files->hashes
	// that have been downloaded previously.
	// If the path isn't found in new update after being read from the previous checksum,
	// it is removed. This allows us fine-grained control over the download process
	// as well as solves a long problem with nuclei-template updates.
	for _, zipTemplateFile := range zipReader.File {
		templateAbsolutePath, skipFile, err := calculateTemplateAbsolutePath(zipTemplateFile.Name)
		if err != nil {
			return nil, err
		}
		if skipFile || templateAbsolutePath == "" {
			continue
		}

		filereader, err := zipTemplateFile.Open()
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(filereader)
		if err != nil {
			filereader.Close()
			return nil, err
		}
		filereader.Close()

		md5Hash := md5.New()
		_, _ = io.Copy(md5Hash, bytes.NewReader(data))
		newHash := hex.EncodeToString(md5Hash.Sum(nil))

		oldTemplateChecksum, checksumOk := templateChecksumsMap[templateAbsolutePath]

		if !checksumOk {
			_, err = db.Queries().AddTemplate(context.Background(), dbsql.AddTemplateParams{
				Name:     filepath.Base(templateAbsolutePath),
				Folder:   repoName,
				Path:     templateAbsolutePath,
				Contents: string(data),
				Hash:     newHash,
			})
			gologger.Info().Msgf("Added template: %s\n", templateAbsolutePath)
			results.additions = append(results.additions, templateAbsolutePath)
		} else if checksumOk && oldTemplateChecksum != newHash {
			err = db.Queries().UpdateTemplate(context.Background(), dbsql.UpdateTemplateParams{
				Updatedat: time.Now(),
				Path:      templateAbsolutePath,
				Contents:  string(data),
				Hash:      newHash,
			})
			gologger.Info().Msgf("Updated template: %s\n", templateAbsolutePath)
			results.modifications = append(results.modifications, templateAbsolutePath)
		}
		if err != nil {
			return nil, err
		}
		results.totalCount++
	}

	// If we don't find the previous file in the newly downloaded list,
	// and it hasn't been changed on the disk, delete it.
	for templatePath, templateChecksums := range templateChecksumsMap {
		_, ok := templateChecksumsMap[templatePath]
		if !ok && templateChecksums[0] == templateChecksums[1] {
			if err = db.Queries().DeleteTemplate(context.Background(), templatePath); err != nil {
				return nil, err
			}
			gologger.Info().Msgf("Deleted template: %s\n", templatePath)
			results.deletions = append(results.deletions, templatePath)
		}
	}
	return results, err
}

func calculateTemplateAbsolutePath(zipFilePath string) (string, bool, error) {
	directory, fileName := filepath.Split(zipFilePath)
	if strings.TrimSpace(fileName) == "" || strings.HasPrefix(fileName, ".") || strings.HasSuffix(fileName, ".md") {
		return "", true, nil
	}

	directoryPathChunks := strings.Split(directory, string(os.PathSeparator))
	relativeDirectoryPathWithoutZipRoot := filepath.Join(directoryPathChunks[1:]...)

	if strings.HasPrefix(relativeDirectoryPathWithoutZipRoot, ".") {
		return "", true, nil
	}
	return filepath.Join(relativeDirectoryPathWithoutZipRoot, fileName), false, nil
}
