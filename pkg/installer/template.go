package installer

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/olekukonko/tablewriter"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/external/customtemplates"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	checkSumFilePerm = 0644
)

var (
	HideProgressBar        = true
	HideUpdateChangesTable = false
	HideReleaseNotes       = true
)

// TemplateUpdateResults contains the results of template update
type templateUpdateResults struct {
	additions     []string
	deletions     []string
	modifications []string
	totalCount    int
}

// String returns markdown table of template update results
func (t *templateUpdateResults) String() string {
	var buff bytes.Buffer
	data := [][]string{
		{
			strconv.Itoa(t.totalCount),
			strconv.Itoa(len(t.additions)),
			strconv.Itoa(len(t.modifications)),
			strconv.Itoa(len(t.deletions)),
		},
	}
	table := tablewriter.NewWriter(&buff)
	table.Header([]string{"Total", "Added", "Modified", "Removed"})
	for _, v := range data {
		_ = table.Append(v)
	}
	_ = table.Render()
	defer func() {
		_ = table.Close()
	}()
	return buff.String()
}

// TemplateManager is a manager for templates.
// It downloads / updates / installs templates.
type TemplateManager struct {
	CustomTemplates        *customtemplates.CustomTemplatesManager // optional if given tries to download custom templates
	DisablePublicTemplates bool                                    // if true,
	// public templates are not downloaded from the GitHub nuclei-templates repository
}

// FreshInstallIfNotExists installs templates if they are not already installed
// if templates directory already exists, it does nothing
func (t *TemplateManager) FreshInstallIfNotExists() error {
	if fileutil.FolderExists(config.DefaultConfig.TemplatesDirectory) {
		return nil
	}
	gologger.Info().Msgf("nuclei-templates are not installed, installing...")
	if err := t.installTemplatesAt(config.DefaultConfig.TemplatesDirectory); err != nil {
		return errkit.Wrapf(err, "failed to install templates at %s", config.DefaultConfig.TemplatesDirectory)
	}
	if t.CustomTemplates != nil {
		t.CustomTemplates.Download(context.TODO())
	}
	return nil
}

// UpdateIfOutdated updates templates if they are outdated
func (t *TemplateManager) UpdateIfOutdated() error {
	// if the templates folder does not exist, it's a fresh installation and do not update
	if !fileutil.FolderExists(config.DefaultConfig.TemplatesDirectory) {
		return t.FreshInstallIfNotExists()
	}

	needsUpdate := config.DefaultConfig.NeedsTemplateUpdate()

	// NOTE(dwisiswant0): if PDTM API data is not available
	// (LatestNucleiTemplatesVersion is empty) but we have a current template
	// version, so we MUST verify against GitHub directly.
	if !needsUpdate && config.DefaultConfig.LatestNucleiTemplatesVersion == "" && config.DefaultConfig.TemplateVersion != "" {
		ghrd, err := updateutils.NewghReleaseDownloader(config.OfficialNucleiTemplatesRepoName)
		if err == nil {
			latestVersion := ghrd.Latest.GetTagName()
			if config.IsOutdatedVersion(config.DefaultConfig.TemplateVersion, latestVersion) {
				needsUpdate = true
				gologger.Debug().Msgf("PDTM API unavailable, verified update needed via GitHub API: %s -> %s", config.DefaultConfig.TemplateVersion, latestVersion)
			}
		}
	}

	if needsUpdate {
		return t.updateTemplatesAt(config.DefaultConfig.TemplatesDirectory)
	}
	return nil
}

// installTemplatesAt installs templates at given directory
func (t *TemplateManager) installTemplatesAt(dir string) error {
	if !fileutil.FolderExists(dir) {
		if err := fileutil.CreateFolder(dir); err != nil {
			return errkit.Wrapf(err, "failed to create directory at %s", dir)
		}
	}
	if t.DisablePublicTemplates {
		gologger.Info().Msgf("Skipping installation of public nuclei-templates")
		return nil
	}
	ghrd, err := updateutils.NewghReleaseDownloader(config.OfficialNucleiTemplatesRepoName)
	if err != nil {
		return errkit.Wrapf(err, "failed to install templates at %s", dir)
	}

	// write templates to disk
	_, err = t.writeTemplatesToDisk(ghrd, dir)
	if err != nil {
		return errkit.Wrapf(err, "failed to write templates to disk at %s", dir)
	}
	gologger.Info().Msgf("Successfully installed nuclei-templates at %s", dir)
	return nil
}

// updateTemplatesAt updates templates at given directory
func (t *TemplateManager) updateTemplatesAt(dir string) error {
	if t.DisablePublicTemplates {
		gologger.Info().Msgf("Skipping update of public nuclei-templates")
		return nil
	}
	// firstly, read checksums from .checksum file these are used to generate stats
	oldchecksums, err := t.getChecksumFromDir(dir)
	if err != nil {
		// if something went wrong, overwrite all files
		oldchecksums = make(map[string]string)
	}

	ghrd, err := updateutils.NewghReleaseDownloader(config.OfficialNucleiTemplatesRepoName)
	if err != nil {
		return errkit.Wrapf(err, "failed to install templates at %s", dir)
	}

	latestVersion := ghrd.Latest.GetTagName()
	currentVersion := config.DefaultConfig.TemplateVersion

	if config.IsOutdatedVersion(currentVersion, latestVersion) {
		gologger.Info().Msgf("Your current nuclei-templates %s are outdated. Latest is %s\n", currentVersion, latestVersion)
	} else {
		gologger.Debug().Msgf("Updating nuclei-templates from %s to %s (forced update)\n", currentVersion, latestVersion)
	}

	// write templates to disk
	writtenPaths, err := t.writeTemplatesToDisk(ghrd, dir)
	if err != nil {
		return err
	}

	// cleanup orphaned templates that exist locally but weren't in the new release
	if err := t.cleanupOrphanedTemplates(dir, writtenPaths); err != nil {
		// log warning but don't fail the update
		gologger.Warning().Msgf("failed to cleanup orphaned templates: %s", err)
	} else {
		// Regenerate metadata (index and checksum) after successful cleanup to ensure
		// metadata accurately reflects the cleaned template tree. This prevents stale
		// index entries and checksum entries for deleted templates.
		if err := t.regenerateTemplateMetadata(dir); err != nil {
			// Log warning but don't fail the update - metadata will be out of sync
			// but templates are cleaned up correctly
			gologger.Warning().Msgf("failed to regenerate template metadata after cleanup: %s", err)
		}
	}

	// get checksums from new templates
	newchecksums, err := t.getChecksumFromDir(dir)
	if err != nil {
		// unlikely this case will happen
		return errkit.Wrapf(err, "failed to get checksums from %s after update", dir)
	}

	// summarize all changes
	results := t.summarizeChanges(oldchecksums, newchecksums)

	// remove deleted templates
	for _, deletion := range results.deletions {
		if err := os.Remove(deletion); err != nil && !os.IsNotExist(err) {
			gologger.Warning().Msgf("failed to remove deleted template %s: %s", deletion, err)
		}
	}

	// print summary
	if results.totalCount > 0 {
		gologger.Info().Msgf("Successfully updated nuclei-templates (%v) to %s. GoodLuck!", ghrd.Latest.GetTagName(), dir)
		if !HideUpdateChangesTable {
			// print summary table
			gologger.Print().Msgf("\nNuclei Templates %s Changelog\n", ghrd.Latest.GetTagName())
			gologger.Print().Msg(results.String())
		}
	} else {
		gologger.Info().Msgf("Successfully updated nuclei-templates (%v) to %s. GoodLuck!", ghrd.Latest.GetTagName(), dir)
	}
	return nil
}

// summarizeChanges summarizes changes between old and new checksums
func (t *TemplateManager) summarizeChanges(old, new map[string]string) *templateUpdateResults {
	results := &templateUpdateResults{}
	for k, v := range new {
		if oldv, ok := old[k]; ok {
			if oldv != v {
				results.modifications = append(results.modifications, k)
			}
		} else {
			results.additions = append(results.additions, k)
		}
	}
	for k := range old {
		if _, ok := new[k]; !ok {
			results.deletions = append(results.deletions, k)
		}
	}
	results.totalCount = len(results.additions) + len(results.deletions) + len(results.modifications)
	return results
}

// getAbsoluteFilePath returns an absolute path where a file should be written based on given uri(i.e., files in zip)
// if a returned path is empty, it means that file should not be written and skipped
func (t *TemplateManager) getAbsoluteFilePath(templateDir, uri string, f fs.FileInfo) string {
	// overwrite .nuclei-ignore every time nuclei-templates are downloaded
	if f.Name() == config.NucleiIgnoreFileName {
		return config.DefaultConfig.GetIgnoreFilePath()
	}
	// skip all meta files
	if !strings.EqualFold(f.Name(), config.NewTemplateAdditionsFileName) {
		if strings.TrimSpace(f.Name()) == "" || strings.HasPrefix(f.Name(), ".") || strings.EqualFold(f.Name(), "README.md") {
			return ""
		}
	}

	// get root or leftmost directory name from path
	// this is in format `projectdiscovery-nuclei-templates-commithash`

	index := strings.Index(uri, "/")
	if index == -1 {
		// zip files does not have directory at all , in this case log error but continue
		gologger.Warning().Msgf("failed to get directory name from uri: %s", uri)
		return filepath.Join(templateDir, uri)
	}
	// separator is also included in rootDir
	rootDirectory := uri[:index+1]
	relPath := strings.TrimPrefix(uri, rootDirectory)

	// if it is a github meta directory skip it
	if stringsutil.HasPrefixAny(relPath, ".github", ".git") {
		return ""
	}

	newPath := filepath.Clean(filepath.Join(templateDir, relPath))

	if !strings.HasPrefix(newPath, templateDir) {
		// we don't allow LFI
		return ""
	}

	if newPath == templateDir || newPath == templateDir+string(os.PathSeparator) {
		// skip writing the folder itself since it already exists
		return ""
	}

	if relPath != "" && f.IsDir() {
		// if uri is a directory, create it
		if err := fileutil.CreateFolder(newPath); err != nil {
			gologger.Warning().Msgf("uri %v: got %s while installing templates", uri, err)
		}
		return ""
	}
	return newPath
}

// writeTemplatesToDisk writes all templates to disk and returns a map of written file paths
// The returned map contains absolute paths of all template files that were successfully written
func (t *TemplateManager) writeTemplatesToDisk(ghrd *updateutils.GHReleaseDownloader, dir string) (*mapsutil.SyncLockMap[string, struct{}], error) {
	localTemplatesIndex, err := config.GetNucleiTemplatesIndex()
	if err != nil {
		gologger.Warning().Msgf("failed to get local nuclei-templates index: %s", err)
		if localTemplatesIndex == nil {
			localTemplatesIndex = map[string]string{} // no-op
		}
	}

	// Track all paths that are successfully written during this update
	writtenPaths := mapsutil.NewSyncLockMap[string, struct{}]()

	callbackFunc := func(uri string, f fs.FileInfo, r io.Reader) error {
		writePath := t.getAbsoluteFilePath(dir, uri, f)
		if writePath == "" {
			// skip writing file
			return nil
		}

		bin, err := io.ReadAll(r)
		if err != nil {
			// if error occurs, iteration also stops
			return errkit.Wrapf(err, "failed to read file %s", uri)
		}
		// TODO: It might be better to just download index file from nuclei templates repo
		// instead of creating it from scratch
		id, _ := config.GetTemplateIDFromReader(bytes.NewReader(bin), uri)
		if id != "" {
			// based on template id, check if we are updating a path of official nuclei template
			if oldPath, ok := localTemplatesIndex[id]; ok {
				if oldPath != writePath {
					// write new template at a new path and delete old template
					if err := os.WriteFile(writePath, bin, f.Mode()); err != nil {
						return errkit.Wrapf(err, "failed to write file %s", uri)
					}
					// Track the new path as written
					_ = writtenPaths.Set(writePath, struct{}{})
					// after successful write, remove old template
					if err := os.Remove(oldPath); err != nil {
						gologger.Warning().Msgf("failed to remove old template %s: %s", oldPath, err)
					}
					return nil
				}
			}
		}
		// no change in template Path of official templates
		if err := os.WriteFile(writePath, bin, f.Mode()); err != nil {
			return errkit.Wrapf(err, "failed to write file %s", uri)
		}
		// Track successfully written paths
		_ = writtenPaths.Set(writePath, struct{}{})
		return nil
	}
	err = ghrd.DownloadSourceWithCallback(!HideProgressBar, callbackFunc)
	if err != nil {
		return nil, errkit.Wrap(err, "failed to download templates")
	}

	if err := config.DefaultConfig.WriteTemplatesConfig(); err != nil {
		return nil, errkit.Wrap(err, "failed to write templates config")
	}
	// update ignore hash after writing new templates
	if err := config.DefaultConfig.UpdateNucleiIgnoreHash(); err != nil {
		return nil, errkit.Wrap(err, "failed to update nuclei ignore hash")
	}

	// update templates version in config file
	if err := config.DefaultConfig.SetTemplatesVersion(ghrd.Latest.GetTagName()); err != nil {
		return nil, errkit.Wrap(err, "failed to update templates version")
	}

	PurgeEmptyDirectories(dir)

	// generate index of all templates
	_ = os.Remove(config.DefaultConfig.GetTemplateIndexFilePath())

	index, err := config.GetNucleiTemplatesIndex()
	if err != nil {
		return nil, errkit.Wrap(err, "failed to get nuclei templates index")
	}

	if err = config.DefaultConfig.WriteTemplatesIndex(index); err != nil {
		return nil, errkit.Wrap(err, "failed to write nuclei templates index")
	}

	if !HideReleaseNotes {
		output := ghrd.Latest.GetBody()
		// adjust colors for both dark / light terminal themes
		r, err := glamour.NewTermRenderer(glamour.WithAutoStyle())
		if err != nil {
			gologger.Error().Msgf("markdown rendering not supported: %v", err)
		}
		if rendered, err := r.Render(output); err == nil {
			output = rendered
		} else {
			gologger.Error().Msg(err.Error())
		}
		gologger.Print().Msgf("\n%v\n\n", output)
	}

	// after installation, create and write checksums to .checksum file
	if err := t.writeChecksumFileInDir(dir); err != nil {
		return nil, err
	}

	return writtenPaths, nil
}

// cleanupOrphanedTemplates removes template files that exist locally but were not part of the new release
// It scans the templates directory for template files and deletes those that are not in the writtenPaths set
// This function handles empty directories gracefully - if the directory is empty, no orphaned files will be found
func (t *TemplateManager) cleanupOrphanedTemplates(dir string, writtenPaths *mapsutil.SyncLockMap[string, struct{}]) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return errkit.Wrapf(err, "failed to get absolute path of templates directory")
	}
	// Use Clean to normalize the path consistently (handles Windows paths better)
	absDir = filepath.Clean(absDir)

	// If directory doesn't exist, there's nothing to clean up
	if !fileutil.FolderExists(absDir) {
		return nil
	}

	// Normalize all written paths to absolute paths for comparison
	normalizedWrittenPaths := mapsutil.NewSyncLockMap[string, struct{}]()
	for path := range writtenPaths.GetAll() {
		absPath, err := filepath.Abs(path)
		if err == nil {
			// Use Clean to normalize the path consistently (handles Windows paths better)
			absPath = filepath.Clean(absPath)
			_ = normalizedWrittenPaths.Set(absPath, struct{}{})
		}
	}

	// Get custom template directories to exclude
	customDirs := config.DefaultConfig.GetAllCustomTemplateDirs()
	customDirAbs := make([]string, 0, len(customDirs))
	for _, customDir := range customDirs {
		if absCustomDir, err := filepath.Abs(customDir); err == nil {
			// Use Clean to normalize the path consistently (handles Windows paths better)
			absCustomDir = filepath.Clean(absCustomDir)
			customDirAbs = append(customDirAbs, absCustomDir)
		}
	}

	var orphanedFiles []string

	// Walk the templates directory to find all template files
	err = filepath.WalkDir(absDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Log but continue walking
			gologger.Debug().Msgf("error accessing path %s during orphan cleanup: %s", path, err)
			return nil
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil
		}
		// Use Clean to normalize the path consistently (handles Windows paths better)
		absPath = filepath.Clean(absPath)

		// Skip custom template directories
		for _, customDir := range customDirAbs {
			if strings.HasPrefix(absPath, customDir) {
				return nil
			}
		}

		// Only process template files
		if !config.IsTemplate(absPath) {
			return nil
		}

		// Skip if this file was written in the new release
		if normalizedWrittenPaths.Has(absPath) {
			return nil
		}

		// This is an orphaned template file
		orphanedFiles = append(orphanedFiles, absPath)
		return nil
	})

	if err != nil {
		return errkit.Wrapf(err, "failed to walk templates directory for orphan cleanup")
	}

	// Delete orphaned files
	for _, orphanPath := range orphanedFiles {
		if err := os.Remove(orphanPath); err != nil {
			if !os.IsNotExist(err) {
				gologger.Warning().Msgf("failed to remove orphaned template %s: %s", orphanPath, err)
			}
		} else {
			gologger.Debug().Msgf("removed orphaned template: %s", orphanPath)
		}
	}

	if len(orphanedFiles) > 0 {
		gologger.Info().Msgf("cleaned up %d orphaned template file(s)", len(orphanedFiles))
	}

	return nil
}

// regenerateTemplateMetadata regenerates template index and checksum files after cleanup operations.
// This ensures the metadata accurately reflects the current state of template files on disk.
func (t *TemplateManager) regenerateTemplateMetadata(dir string) error {
	// Purge empty directories that may have been left after cleanup
	PurgeEmptyDirectories(dir)

	// Ensure templates directory exists (it may have been purged if empty)
	if !fileutil.FolderExists(dir) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errkit.Wrapf(err, "failed to recreate templates directory %s after purge", dir)
		}
	}

	// Remove old index file and regenerate it from current templates on disk
	indexFilePath := config.DefaultConfig.GetTemplateIndexFilePath()
	if err := os.Remove(indexFilePath); err != nil && !os.IsNotExist(err) {
		return errkit.Wrapf(err, "failed to remove old index file %s", indexFilePath)
	}

	// Force regeneration by ensuring the file doesn't exist (handles Windows file handle issues)
	// GetNucleiTemplatesIndex will scan the directory if the file doesn't exist
	index, err := config.GetNucleiTemplatesIndex()
	if err != nil {
		return errkit.Wrap(err, "failed to regenerate nuclei templates index after cleanup")
	}

	// Filter out any entries that don't actually exist on disk (Windows file deletion timing issues)
	filteredIndex := make(map[string]string)
	for id, path := range index {
		if fileutil.FileExists(path) {
			filteredIndex[id] = path
		}
	}

	if err = config.DefaultConfig.WriteTemplatesIndex(filteredIndex); err != nil {
		return errkit.Wrap(err, "failed to write nuclei templates index after cleanup")
	}

	// Regenerate checksum file to reflect current templates on disk
	if err := t.writeChecksumFileInDir(dir); err != nil {
		return errkit.Wrap(err, "failed to regenerate checksum file after cleanup")
	}

	return nil
}

// getChecksumFromDir returns a map containing checksums (md5 hash) of all yaml files (with .yaml extension)
// if .checksum file does not exist, checksums are calculated and returned
func (t *TemplateManager) getChecksumFromDir(dir string) (map[string]string, error) {
	checksumFilePath := config.DefaultConfig.GetChecksumFilePath()
	if fileutil.FileExists(checksumFilePath) {
		checksums, err := os.ReadFile(checksumFilePath)
		if err == nil {
			allChecksums := make(map[string]string)
			for _, v := range strings.Split(string(checksums), ";") {
				v = strings.TrimSpace(v)
				tmparr := strings.Split(v, ",")
				if len(tmparr) != 2 {
					continue
				}
				allChecksums[tmparr[0]] = tmparr[1]
			}
			return allChecksums, nil
		}
	}
	return t.calculateChecksumMap(dir)
}

// writeChecksumFileInDir creates checksums of all yaml files in given directory
// and writes them to a file named .checksum
func (t *TemplateManager) writeChecksumFileInDir(dir string) error {
	checksumMap, err := t.calculateChecksumMap(dir)
	if err != nil {
		return err
	}
	var buff bytes.Buffer
	for k, v := range checksumMap {
		buff.WriteString(k)
		buff.WriteString(",")
		buff.WriteString(v)
		buff.WriteString(";")
	}
	return os.WriteFile(config.DefaultConfig.GetChecksumFilePath(), buff.Bytes(), checkSumFilePerm)
}

// getChecksumMap returns a map containing checksums (md5 hash) of all yaml files (with .yaml extension)
func (t *TemplateManager) calculateChecksumMap(dir string) (map[string]string, error) {
	// getchecksumMap walks given directory `dir` and returns a map containing
	// checksums (md5 hash) of all yaml files (with .yaml extension) and the
	// format is map[filePath]checksum
	checksumMap := map[string]string{}

	getChecksum := func(filepath string) (string, error) {
		// return md5 hash of the file
		bin, err := os.ReadFile(filepath)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", md5.Sum(bin)), nil
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// skip checksums of custom templates i.e github and s3
		if stringsutil.HasPrefixAny(path, config.DefaultConfig.GetAllCustomTemplateDirs()...) {
			return nil
		}

		// current implementations calculates checksums of all files (including .yaml,.txt,.md,.json etc)
		if !d.IsDir() {
			checksum, err := getChecksum(path)
			if err != nil {
				return err
			}
			checksumMap[path] = checksum
		}
		return nil
	})
	return checksumMap, errkit.Wrap(err, "failed to calculate checksums of templates")
}
