package installer

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/charmbracelet/glamour"
	"github.com/google/go-github/v30/github"
	"github.com/olekukonko/tablewriter"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/external/customtemplates"
	filepathutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/filepath"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
)

const (
	checkSumFilePerm              = 0644
	templateOutputTemporaryPrefix = ".nuclei-write-"
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
	return withTemplatesUpdateLock(t.updateIfOutdatedLocked)
}

func (t *TemplateManager) updateIfOutdatedLocked() error {
	// if the templates folder does not exist, it's a fresh installation and do not update
	if !fileutil.FolderExists(config.DefaultConfig.TemplatesDirectory) {
		return t.FreshInstallIfNotExists()
	}

	if err := recoverTemplateOwnership(config.DefaultConfig.TemplatesDirectory); err != nil {
		return errkit.Wrapf(err, "failed to recover template ownership at %s", config.DefaultConfig.TemplatesDirectory)
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

	if err := recoverTemplateOwnership(dir); err != nil {
		return errkit.Wrapf(err, "failed to recover template ownership at %s", dir)
	}

	ghrd, err := updateutils.NewghReleaseDownloader(config.OfficialNucleiTemplatesRepoName)
	if err != nil {
		return errkit.Wrapf(err, "failed to install templates at %s", dir)
	}

	// write templates to disk
	writtenOutputs, writeErr := t.writeTemplatesToDisk(ghrd, dir)
	if _, finalizeErr := t.finalizeTemplateWrite(config.DefaultConfig, writtenOutputs, ghrd.Latest.GetTagName(), writeErr); finalizeErr != nil {
		return errkit.Wrapf(finalizeErr, "failed to finalize template installation at %s", dir)
	}

	gologger.Info().Msgf("Successfully installed nuclei-templates at %s", dir)

	return nil
}

type templateArchiveFetcher func(version string) (*bytes.Reader, error)

func commitTemplateVersion(cfg *config.Config, version string) error {
	previousVersion := cfg.TemplateVersion
	if err := cfg.SetTemplatesVersion(version); err != nil {
		cfg.TemplateVersion = previousVersion

		return err
	}

	return nil
}

func (t *TemplateManager) finalizeTemplateRelease(cfg *config.Config, writtenOutputs map[string]string, version string) (map[string]string, error) {
	dir := cfg.TemplatesDirectory

	var finalizationErr error

	if err := reconcileTemplateOwnership(dir, writtenOutputs); err != nil {
		finalizationErr = errors.Join(finalizationErr, fmt.Errorf("reconcile template ownership: %w", err))
	}

	if err := cfg.UpdateNucleiIgnoreHash(); err != nil {
		finalizationErr = errors.Join(finalizationErr, errkit.Wrap(err, "failed to update nuclei ignore hash"))
	}

	checksums, err := t.regenerateTemplateMetadata(cfg)
	if err != nil {
		finalizationErr = errors.Join(finalizationErr, fmt.Errorf("regenerate template metadata: %w", err))
	}

	if finalizationErr != nil {
		return nil, finalizationErr
	}

	if err := commitTemplateVersion(cfg, version); err != nil {
		return nil, errkit.Wrap(err, "failed to update templates version")
	}

	return checksums, nil
}

func (t *TemplateManager) finalizeTemplateWrite(cfg *config.Config, writtenOutputs map[string]string, version string, writeErr error) (map[string]string, error) {
	if writeErr != nil {
		if ownershipErr := recordPartialTemplateOwnership(cfg.TemplatesDirectory, writtenOutputs); ownershipErr != nil {
			writeErr = errors.Join(writeErr, fmt.Errorf("record ownership for partially written templates: %w", ownershipErr))
		}

		return nil, writeErr
	}

	return t.finalizeTemplateRelease(cfg, writtenOutputs, version)
}

func (t *TemplateManager) bootstrapTemplateOwnership(dir, version string, fetchArchive templateArchiveFetcher) error {
	if _, err := loadTemplateOwnership(dir); err == nil {
		return nil
	} else if errors.Is(err, errTemplateOwnershipInvalid) {
		quarantines, recoveryErr := listTemplateOwnershipQuarantines(dir)
		if recoveryErr != nil {
			return errors.Join(err, recoveryErr)
		}

		restoreStates, recoveryErr := listTemplateOwnershipRestoreStates(dir)
		if recoveryErr != nil {
			return errors.Join(err, recoveryErr)
		}

		if len(quarantines) > 0 || len(restoreStates) > 0 {
			return err
		}

		gologger.Verbose().Msgf("Replacing invalid template ownership metadata without retiring prior templates: %s", err)

		return nil
	} else if !errors.Is(err, errTemplateOwnershipMissing) {
		return err
	}

	version = strings.TrimSpace(version)
	if version == "" {
		return nil
	}

	archive, err := fetchArchive(version)
	if err != nil {
		gologger.Verbose().Msgf("Continuing template update without prior ownership for %q: %s", version, err)
		return nil
	}

	if err := t.bootstrapTemplateOwnershipFromArchive(dir, archive); err != nil {
		if errors.Is(err, errTemplateOwnershipArchiveInvalid) {
			gologger.Verbose().Msgf("Continuing template update without prior ownership for %q: %s", version, err)
			return nil
		}

		return fmt.Errorf("build ownership from prior template release %q: %w", version, err)
	}

	return nil
}

func fetchTemplateReleaseArchive(version string) (*bytes.Reader, error) {
	ctx := context.Background()
	httpClient := &http.Client{Timeout: updateutils.DownloadUpdateTimeout}
	client := github.NewClient(httpClient)
	archiveURL, _, err := client.Repositories.GetArchiveLink(
		ctx,
		updateutils.Organization,
		config.OfficialNucleiTemplatesRepoName,
		github.Zipball,
		&github.RepositoryContentGetOptions{Ref: version},
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve prior template release %q archive: %w", version, err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create prior template release %q archive request: %w", version, err)
	}

	var contents bytes.Buffer
	response, err := client.Do(ctx, request, &contents)
	if err != nil {
		return nil, fmt.Errorf("download prior template release %q: %w", version, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download prior template release %q: unexpected HTTP status %s", version, response.Status)
	}

	return bytes.NewReader(contents.Bytes()), nil
}

func (t *TemplateManager) bootstrapTemplateOwnershipFromArchive(dir string, archive *bytes.Reader) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("get absolute templates directory: %w", err)
	}

	manifest := &templateOwnershipManifest{
		Version: templateOwnershipVersion,
		Files:   make(map[string]string),
	}

	callback := func(uri string, fileInfo fs.FileInfo, reader io.Reader) error {
		if fileInfo.IsDir() {
			return nil
		}

		_, writePath := t.getTemplateOutputLocation(absDir, uri, fileInfo)
		if writePath == "" {
			return nil
		}

		if !config.IsTemplate(writePath) {
			return nil
		}

		relativePath, err := filepath.Rel(absDir, writePath)
		if err != nil {
			return fmt.Errorf("make prior template path %q relative to %q: %w", writePath, absDir, err)
		}

		relativePath = filepath.ToSlash(relativePath)
		if !config.IsTemplate(relativePath) {
			return nil
		}

		if err := validateTemplateOwnershipPath(relativePath); err != nil {
			return err
		}

		contents, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("read prior template %q: %w", uri, err)
		}

		manifest.Files[relativePath] = templateDigest(contents)
		return nil
	}

	if err := updateutils.UnpackAssetWithCallback(updateutils.Zip, archive, callback); err != nil {
		return fmt.Errorf("%w: unpack prior template release: %v", errTemplateOwnershipArchiveInvalid, err)
	}

	return writeTemplateOwnership(absDir, manifest)
}

// updateTemplatesAt updates templates at given directory
func (t *TemplateManager) updateTemplatesAt(dir string) error {
	if t.DisablePublicTemplates {
		gologger.Info().Msgf("Skipping update of public nuclei-templates")

		return nil
	}

	if err := t.bootstrapTemplateOwnership(dir, config.DefaultConfig.TemplateVersion, fetchTemplateReleaseArchive); err != nil {
		return errkit.Wrapf(err, "failed to migrate template ownership at %s", dir)
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
	writtenOutputs, writeErr := t.writeTemplatesToDisk(ghrd, dir)
	newchecksums, finalizeErr := t.finalizeTemplateWrite(config.DefaultConfig, writtenOutputs, latestVersion, writeErr)
	if finalizeErr != nil {
		return errkit.Wrapf(finalizeErr, "failed to finalize template update at %s", dir)
	}

	// summarize all changes
	results := t.summarizeChanges(oldchecksums, newchecksums)

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

// getTemplateOutputLocation returns the safe root and absolute output path for an archive entry.
// An empty output path means the entry should be skipped.
func (t *TemplateManager) getTemplateOutputLocation(templateDir, uri string, f fs.FileInfo) (string, string) {
	// overwrite .nuclei-ignore every time nuclei-templates are downloaded
	if f.Name() == config.NucleiIgnoreFileName {
		return config.DefaultConfig.TemplatesDirectory, config.DefaultConfig.GetActiveIgnoreFilePath()
	}

	// skip all meta files
	if !strings.EqualFold(f.Name(), config.NewTemplateAdditionsFileName) {
		if strings.TrimSpace(f.Name()) == "" || strings.HasPrefix(f.Name(), ".") || strings.EqualFold(f.Name(), "README.md") {
			return "", ""
		}
	}

	// get root or leftmost directory name from path
	// this is in format `projectdiscovery-nuclei-templates-commithash`

	index := strings.Index(uri, "/")
	if index == -1 {
		// zip files does not have directory at all , in this case log error but continue
		gologger.Warning().Msgf("failed to get directory name from uri: %s", uri)
		// Even in this fallback path the entry name comes from a downloaded
		// archive, so we must still verify it cannot escape templateDir.
		// On Windows in particular, an entry named "..\\foo" has no slash but
		// is a parent reference that filepath.Join+Clean will happily resolve
		// to outside the configured templates directory.
		fallbackPath := filepath.Clean(filepath.Join(templateDir, uri))
		if !filepathutil.IsPathWithinDirectory(fallbackPath, templateDir) {
			return "", ""
		}
		return templateDir, fallbackPath
	}
	// separator is also included in rootDir
	rootDirectory := uri[:index+1]
	relPath := strings.TrimPrefix(uri, rootDirectory)

	// if it is a github meta directory skip it
	if stringsutil.HasPrefixAny(relPath, ".github", ".git") {
		return "", ""
	}

	newPath := filepath.Clean(filepath.Join(templateDir, relPath))

	if !filepathutil.IsPathWithinDirectory(newPath, templateDir) || !filepathutil.IsPathWithinDirectory(filepath.Dir(newPath), templateDir) {
		// we don't allow LFI
		return "", ""
	}

	if filepath.Clean(newPath) == filepath.Clean(templateDir) {
		// skip writing the folder itself since it already exists
		return "", ""
	}

	return templateDir, newPath
}

// writeTemplatesToDisk writes release outputs to disk and returns their digests.
// The returned map includes every successfully written output; ownership
// reconciliation filters it to official template paths.
func (t *TemplateManager) writeTemplatesToDisk(ghrd *updateutils.GHReleaseDownloader, dir string) (map[string]string, error) {
	writtenOutputs := make(map[string]string)
	touchedDirectories := make(map[string]struct{})

	callbackFunc := func(uri string, f fs.FileInfo, r io.Reader) error {
		if f.IsDir() {
			return nil
		}

		rootDir, writePath := t.getTemplateOutputLocation(dir, uri, f)
		if writePath == "" {
			// skip writing file
			return nil
		}

		bin, err := io.ReadAll(r)
		if err != nil {
			// if error occurs, iteration also stops
			return errkit.Wrapf(err, "failed to read file %s", uri)
		}

		outputResult, outputErr := writeTemplateOutput(rootDir, writePath, bin, f.Mode())
		for _, directory := range outputResult.touchedDirectories {
			touchedDirectories[directory] = struct{}{}
		}

		if outputErr != nil {
			return errkit.Wrapf(outputErr, "failed to write file %s", uri)
		}

		writtenOutputs[writePath] = templateDigest(bin)

		return nil
	}

	var writeErr error

	if err := ghrd.DownloadSourceWithCallback(!HideProgressBar, callbackFunc); err != nil {
		writeErr = errkit.Wrap(err, "failed to download templates")
	}

	if err := syncTemplateOutputDirectories(touchedDirectories, syncTemplateOwnershipDirectory); err != nil {
		writeErr = errors.Join(writeErr, errkit.Wrap(err, "failed to sync template output directories"))
	}

	if writeErr != nil {
		return writtenOutputs, writeErr
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

	return writtenOutputs, nil
}

func syncTemplateOutputDirectories(directories map[string]struct{}, syncDirectory func(*os.Root, string) error) error {
	var syncErrors error

	for directory := range directories {
		root, err := os.OpenRoot(directory)
		if err != nil {
			syncErrors = errors.Join(syncErrors, fmt.Errorf("open output directory %q: %w", directory, err))
			continue
		}

		syncErr := syncDirectory(root, ".")
		closeErr := root.Close()
		if syncErr != nil {
			syncErrors = errors.Join(syncErrors, fmt.Errorf("sync output directory %q: %w", directory, syncErr))
		}
		if closeErr != nil {
			syncErrors = errors.Join(syncErrors, fmt.Errorf("close output directory %q: %w", directory, closeErr))
		}
	}

	return syncErrors
}

// templateOutputWriteResult records filesystem state that must be finalized
// even when the associated write returns an error.
type templateOutputWriteResult struct {
	touchedDirectories []string
}

func writeTemplateOutput(rootDir, writePath string, contents []byte, mode fs.FileMode) (templateOutputWriteResult, error) {
	var result templateOutputWriteResult
	relativePath, err := filepath.Rel(rootDir, writePath)
	if err != nil {
		return result, err
	}

	if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(os.PathSeparator)) || filepath.IsAbs(relativePath) {
		return result, fmt.Errorf("output path %q escapes root %q", writePath, rootDir)
	}

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return result, fmt.Errorf("open output root %q: %w", rootDir, err)
	}
	defer func() { _ = root.Close() }()

	parent := filepath.Dir(relativePath)
	if parent != "." {
		parentsToSync, err := createTemplateDirectories(root, parent)
		for _, parentToSync := range parentsToSync {
			result.touchedDirectories = append(result.touchedDirectories, filepath.Clean(filepath.Join(rootDir, parentToSync)))
		}
		if err != nil {
			return result, fmt.Errorf("create output parent %q: %w", parent, err)
		}
	}
	result.touchedDirectories = append(result.touchedDirectories, filepath.Dir(writePath))

	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return result, fmt.Errorf("generate temporary output name: %w", err)
	}

	temporaryPath := filepath.Join(parent, fmt.Sprintf("%s%x", templateOutputTemporaryPrefix, randomSuffix))
	temporaryMode := mode.Perm()
	preserveMode := false

	if info, err := root.Lstat(relativePath); err == nil && info.Mode().IsRegular() {
		temporaryMode = 0o600
		mode = info.Mode()
		preserveMode = true
	} else if err != nil && !os.IsNotExist(err) {
		return result, fmt.Errorf("inspect existing output %q: %w", relativePath, err)
	}

	temporary, err := root.OpenFile(temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, temporaryMode)
	if err != nil {
		return result, fmt.Errorf("create temporary output %q: %w", temporaryPath, err)
	}

	defer func() {
		_ = temporary.Close()
		_ = root.Remove(temporaryPath)
	}()

	if _, err := temporary.Write(contents); err != nil {
		return result, fmt.Errorf("write temporary output %q: %w", temporaryPath, err)
	}

	if preserveMode {
		if err := temporary.Chmod(mode.Perm()); err != nil {
			return result, fmt.Errorf("preserve output mode %q: %w", temporaryPath, err)
		}
	}

	// A release contains thousands of files, so syncing every temporary file
	// makes installation latency scale with storage flush latency. Closing and
	// renaming keeps replacement atomic; touched directories are synced once
	// after extraction and before ownership or version finalization.
	if err := temporary.Close(); err != nil {
		return result, fmt.Errorf("close temporary output %q: %w", temporaryPath, err)
	}

	if err := root.Rename(temporaryPath, relativePath); err != nil {
		return result, fmt.Errorf("replace output %q: %w", relativePath, err)
	}

	return result, nil
}

// regenerateTemplateMetadata rebuilds the index and checksums from the finalized on-disk tree.
func (t *TemplateManager) regenerateTemplateMetadata(cfg *config.Config) (map[string]string, error) {
	dir := cfg.TemplatesDirectory

	// Purge empty directories before rebuilding metadata.
	PurgeEmptyDirectories(dir)

	// Ensure the templates directory exists if the finalized tree is empty.
	if !fileutil.FolderExists(dir) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, errkit.Wrapf(err, "failed to recreate templates directory %s after purge", dir)
		}
	}

	// Remove old index file and regenerate it from current templates on disk
	indexFilePath := cfg.GetTemplateIndexFilePath()
	if err := os.Remove(indexFilePath); err != nil && !os.IsNotExist(err) {
		return nil, errkit.Wrapf(err, "failed to remove old index file %s", indexFilePath)
	}

	// Force regeneration by ensuring the file doesn't exist (handles Windows file handle issues)
	// GetNucleiTemplatesIndex will scan the directory if the file doesn't exist
	index, err := config.GetNucleiTemplatesIndex()
	if err != nil {
		return nil, errkit.Wrap(err, "failed to regenerate nuclei templates index")
	}

	// Filter out any entries that don't actually exist on disk (Windows file deletion timing issues)
	filteredIndex := make(map[string]string)
	for id, path := range index {
		if fileutil.FileExists(path) {
			filteredIndex[id] = path
		}
	}

	if err = cfg.WriteTemplatesIndex(filteredIndex); err != nil {
		return nil, errkit.Wrap(err, "failed to write regenerated nuclei templates index")
	}

	checksumMap, err := t.calculateChecksumMap(dir)
	if err != nil {
		return nil, errkit.Wrap(err, "failed to regenerate checksum map")
	}

	if err := writeChecksumMap(cfg, checksumMap); err != nil {
		return nil, errkit.Wrap(err, "failed to write regenerated checksum file")
	}

	return checksumMap, nil
}

// getChecksumFromDir returns a map containing checksums (md5 hash) of all yaml files (with .yaml extension)
// if .checksum file does not exist, checksums are calculated and returned
func (t *TemplateManager) getChecksumFromDir(dir string) (map[string]string, error) {
	checksumFilePath := config.DefaultConfig.GetChecksumFilePath()
	if fileutil.FileExists(checksumFilePath) {
		checksums, err := os.ReadFile(checksumFilePath)
		if err == nil {
			allChecksums := make(map[string]string)
			checksumStr := string(checksums)
			for v := range strings.SplitSeq(checksumStr, ";") {
				v = strings.TrimSpace(v)
				// Strict two-field parse: paths may contain commas (Cut would parse wrong).
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

// writeChecksumFileInDir creates checksums of all YAML files in dir and writes
// them to the configured checksum file.
func (t *TemplateManager) writeChecksumFileInDir(dir string) error {
	checksumMap, err := t.calculateChecksumMap(dir)
	if err != nil {
		return err
	}

	return writeChecksumMap(config.DefaultConfig, checksumMap)
}

func writeChecksumMap(cfg *config.Config, checksumMap map[string]string) error {
	var buff bytes.Buffer

	for k, v := range checksumMap {
		buff.WriteString(k)
		buff.WriteString(",")
		buff.WriteString(v)
		buff.WriteString(";")
	}

	return os.WriteFile(cfg.GetChecksumFilePath(), buff.Bytes(), checkSumFilePerm)
}

func isTemplateOutputTemporary(name string) bool {
	suffix, found := strings.CutPrefix(name, templateOutputTemporaryPrefix)
	if !found {
		return false
	}
	if isLowerHex(suffix, 32) {
		return true
	}
	pathDigest, token, found := strings.Cut(suffix, "-")
	return found && isLowerHex(pathDigest, 32) && isLowerHex(token, 32)
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

		if !d.IsDir() && isTemplateOutputTemporary(filepath.Base(path)) {
			return nil
		}

		if filepath.Dir(path) == filepath.Clean(dir) {
			name := filepath.Base(path)
			if name == templateOwnershipFileName || strings.HasPrefix(name, templateOwnershipTemporaryPrefix) || strings.HasPrefix(name, templateOwnershipRetiredPrefix) || strings.HasPrefix(name, templateOwnershipRestorePrefix) {
				return nil
			}
		}

		// skip checksums of custom templates i.e github and s3
		if filepathutil.IsPathWithinAnyDirectory(path, config.DefaultConfig.GetAllCustomTemplateDirs()...) {
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
