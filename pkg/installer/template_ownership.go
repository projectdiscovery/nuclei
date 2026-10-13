package installer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

const (
	templateOwnershipFileName        = ".templates-ownership"
	templateOwnershipVersion         = 1
	templateOwnershipTemporaryPrefix = templateOwnershipFileName + ".tmp-"
	templateOwnershipRetiredPrefix   = templateOwnershipFileName + ".retired-"
	templateOwnershipRestorePrefix   = templateOwnershipFileName + ".restore-"
)

type templateRestoreState struct {
	retiredPath   string
	temporaryPath string
	statePath     string
	kind          templateRestoreKind
	digest        string
}

type templateRestoreKind string

const (
	templateRestoreCopy templateRestoreKind = "copy"
	templateRestoreMove templateRestoreKind = "move"
)

type templateOwnershipRecoveryEntry struct {
	relativePath string
	digest       string
}

var (
	errTemplateOwnershipMissing        = errors.New("template ownership metadata is missing")
	errTemplateOwnershipInvalid        = errors.New("template ownership metadata is invalid")
	errTemplateOwnershipArchiveInvalid = errors.New("prior template release archive is invalid")
)

type templateOwnershipManifest struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"`
}

// reconcileTemplateOwnership removes only unchanged files owned by the
// previous release, then records the files owned by the current release.
func reconcileTemplateOwnership(dir string, writtenOutputs map[string]string) error {
	current, err := buildTemplateOwnership(dir, writtenOutputs)
	if err != nil {
		return err
	}

	var reconcileErr error

	previous, loadErr := loadTemplateOwnership(dir)
	if loadErr == nil {
		ownershipToRetry, cleanupErr := cleanupRetiredTemplates(dir, previous, current)
		for relativePath, digest := range ownershipToRetry {
			current.Files[relativePath] = digest
		}
		reconcileErr = cleanupErr
	} else if !errors.Is(loadErr, errTemplateOwnershipMissing) {
		gologger.Warning().Msgf("Skipping retired template cleanup: %s", loadErr)
	}

	if writeErr := writeTemplateOwnership(dir, current); writeErr != nil {
		reconcileErr = errors.Join(reconcileErr, writeErr)
	}

	return reconcileErr
}

// recordPartialTemplateOwnership merges successfully written outputs into the
// previous manifest without retiring paths that the interrupted release did not visit.
func recordPartialTemplateOwnership(dir string, writtenOutputs map[string]string) error {
	if len(writtenOutputs) == 0 {
		return nil
	}

	partial, err := buildTemplateOwnership(dir, writtenOutputs)
	if err != nil {
		return err
	}
	if len(partial.Files) == 0 {
		return nil
	}

	previous, err := loadTemplateOwnership(dir)
	if err == nil {
		for relativePath, digest := range previous.Files {
			if _, wasWritten := partial.Files[relativePath]; !wasWritten {
				partial.Files[relativePath] = digest
			}
		}
	} else if !errors.Is(err, errTemplateOwnershipMissing) && !errors.Is(err, errTemplateOwnershipInvalid) {
		return err
	}

	return writeTemplateOwnership(dir, partial)
}

func buildTemplateOwnership(dir string, writtenOutputs map[string]string) (*templateOwnershipManifest, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("get absolute templates directory: %w", err)
	}

	root, err := os.OpenRoot(absDir)
	if err != nil {
		return nil, fmt.Errorf("open templates directory %q: %w", absDir, err)
	}

	defer func() { _ = root.Close() }()

	manifest := &templateOwnershipManifest{
		Version: templateOwnershipVersion,
		Files:   make(map[string]string),
	}

	for writtenPath, digest := range writtenOutputs {
		if !config.IsTemplate(writtenPath) {
			continue
		}

		absPath, err := filepath.Abs(writtenPath)
		if err != nil {
			return nil, fmt.Errorf("get absolute template path %q: %w", writtenPath, err)
		}

		relativePath, err := filepath.Rel(absDir, absPath)
		if err != nil {
			return nil, fmt.Errorf("make template path %q relative to %q: %w", absPath, absDir, err)
		}
		if relativePath == ".." || strings.HasPrefix(relativePath, ".."+string(os.PathSeparator)) {
			continue
		}

		relativePath = filepath.ToSlash(relativePath)
		if !config.IsTemplate(relativePath) {
			continue
		}

		hasSymlink, err := templatePathHasSymlink(root, relativePath)
		if err != nil {
			return nil, fmt.Errorf("inspect installed template path %q: %w", absPath, err)
		}

		if hasSymlink {
			return nil, fmt.Errorf("installed template path %q contains a symbolic link", absPath)
		}

		manifest.Files[relativePath] = digest
	}

	if err := validateTemplateOwnership(manifest); err != nil {
		return nil, fmt.Errorf("validate current template ownership: %w", err)
	}

	return manifest, nil
}

func templateDigest(contents []byte) string {
	digest := sha256.Sum256(contents)

	return hex.EncodeToString(digest[:])
}

// recoverTemplateOwnership resolves cleanup interrupted after a template was
// quarantined. Callers run this before writing a new release so a reintroduced
// path cannot hide or overwrite the quarantined contents before recovery.
func recoverTemplateOwnership(dir string) error {
	quarantineEntries, err := listTemplateOwnershipQuarantines(dir)
	if err != nil {
		return err
	}

	restoreEntries, err := listTemplateOwnershipRestoreStates(dir)
	if err != nil {
		return err
	}

	if len(quarantineEntries) == 0 && len(restoreEntries) == 0 {
		return nil
	}

	previous, err := loadTemplateOwnership(dir)
	if err != nil {
		return fmt.Errorf("load template ownership for recovery: %w", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open templates directory %q for recovery: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	expected := make(map[string]templateOwnershipRecoveryEntry, len(previous.Files))
	expectedRestorePrefixes := make(map[string]templateOwnershipRecoveryEntry, len(previous.Files))
	for relativePath, previousDigest := range previous.Files {
		expected[retiredTemplateQuarantinePath(relativePath)] = templateOwnershipRecoveryEntry{relativePath: relativePath, digest: previousDigest}
		expectedRestorePrefixes[templateRestoreStatePrefix(filepath.FromSlash(relativePath))] = templateOwnershipRecoveryEntry{relativePath: relativePath, digest: previousDigest}
	}

	var recoveryErr error

	handledQuarantines := make(map[string]struct{})

	for _, statePath := range restoreEntries {
		entry, state, stateErr := parseTemplateRestoreState(root, statePath, expectedRestorePrefixes)
		if stateErr != nil {
			recoveryErr = errors.Join(recoveryErr, stateErr)
			continue
		}

		quarantinePath := retiredTemplateQuarantinePath(entry.relativePath)
		if _, err := root.Lstat(quarantinePath); err == nil {
			completed, resumeErr := resumeTemplateRestoreState(root, state, quarantinePath, root.Link)
			if resumeErr != nil {
				recoveryErr = errors.Join(recoveryErr, fmt.Errorf("resume template restore %q: %w", entry.relativePath, resumeErr))
				handledQuarantines[quarantinePath] = struct{}{}

				continue
			}

			if completed {
				handledQuarantines[quarantinePath] = struct{}{}
			}

			continue
		} else if !os.IsNotExist(err) {
			recoveryErr = errors.Join(recoveryErr, fmt.Errorf("inspect quarantine for restore state %q: %w", statePath, err))

			continue
		}

		if err := cleanupCommittedTemplateRestore(root, state); err != nil {
			recoveryErr = errors.Join(recoveryErr, fmt.Errorf("clean up committed template restore %q: %w", entry.relativePath, err))
		}
	}

	for _, quarantinePath := range quarantineEntries {
		if _, handled := handledQuarantines[quarantinePath]; handled {
			continue
		}

		entry, ok := expected[quarantinePath]
		if !ok {
			recoveryErr = errors.Join(recoveryErr, fmt.Errorf("unrecognized template ownership quarantine %q", quarantinePath))
			continue
		}

		if _, err := cleanupQuarantinedTemplate(root, filepath.FromSlash(entry.relativePath), quarantinePath, entry.digest); err != nil {
			recoveryErr = errors.Join(recoveryErr, fmt.Errorf("recover quarantined retired template %q: %w", entry.relativePath, err))
		}
	}

	return recoveryErr
}

func resumeTemplateRestoreState(root *os.Root, state templateRestoreState, quarantinePath string, link func(string, string) error) (bool, error) {
	if _, err := root.Lstat(state.retiredPath); err == nil {
		if state.kind == templateRestoreMove {
			return false, fmt.Errorf("move restore state %q still has quarantine %q", state.statePath, quarantinePath)
		}

		completed, err := finishInterruptedTemplateRestore(root, state.retiredPath, quarantinePath, syncTemplateOwnershipFile)
		if err != nil || completed {
			return completed, err
		}

		if err := rollbackTemplateRestoreState(root, state); err != nil {
			return false, err
		}

		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("inspect restored template %q: %w", state.retiredPath, err)
	}

	if info, err := root.Lstat(state.temporaryPath); err == nil {
		if state.kind != templateRestoreCopy {
			return false, fmt.Errorf("move restore state %q has unexpected temporary file %q", state.statePath, state.temporaryPath)
		}

		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("temporary restored template %q is not a regular file", state.temporaryPath)
		}

		if err := publishTemplateRestore(root, state.temporaryPath, state.retiredPath, link); err != nil {
			return false, err
		}

		return false, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("inspect temporary restored template %q: %w", state.temporaryPath, err)
	}

	if state.kind != templateRestoreMove {
		return false, fmt.Errorf("copy restore state %q lost temporary file %q before publication", state.statePath, state.temporaryPath)
	}

	if err := relocateTemplateRestoreNoReplace(root, quarantinePath, state.retiredPath); err != nil {
		return false, err
	}

	if err := cleanupTemplateRestoreState(root, state); err != nil {
		return false, err
	}

	return true, nil
}

func listTemplateOwnershipRestoreStates(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("inspect templates directory %q for restore state: %w", dir, err)
	}

	states := make([]string, 0)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), templateOwnershipRestorePrefix) {
			states = append(states, entry.Name())
		}
	}

	return states, nil
}

func parseTemplateRestoreState(root *os.Root, statePath string, expected map[string]templateOwnershipRecoveryEntry) (templateOwnershipRecoveryEntry, templateRestoreState, error) {
	for prefix, entry := range expected {
		token, found := strings.CutPrefix(statePath, prefix)
		if !found || !isLowerHex(token, 32) {
			continue
		}

		retiredPath := filepath.FromSlash(entry.relativePath)
		state := templateRestoreState{
			retiredPath:   retiredPath,
			temporaryPath: templateRestoreTemporaryPath(retiredPath) + "-" + token,
			statePath:     statePath,
		}

		if err := loadTemplateRestoreState(root, &state); err != nil {
			return templateOwnershipRecoveryEntry{}, templateRestoreState{}, err
		}

		return entry, state, nil
	}

	return templateOwnershipRecoveryEntry{}, templateRestoreState{}, fmt.Errorf("unrecognized template restore state %q", statePath)
}

func listTemplateOwnershipQuarantines(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("inspect templates directory %q for recovery: %w", dir, err)
	}

	quarantines := make([]string, 0)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), templateOwnershipRetiredPrefix) {
			quarantines = append(quarantines, entry.Name())
		}
	}

	return quarantines, nil
}

func loadTemplateOwnership(dir string) (*templateOwnershipManifest, error) {
	manifestPath := filepath.Join(dir, templateOwnershipFileName)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open templates directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	info, err := root.Lstat(templateOwnershipFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", errTemplateOwnershipMissing, manifestPath)
		}

		return nil, fmt.Errorf("inspect template ownership metadata %q: %w", manifestPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("template ownership metadata %q is a symbolic link", manifestPath)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("template ownership metadata %q is not a regular file", manifestPath)
	}

	contents, err := root.ReadFile(templateOwnershipFileName)
	if err != nil {
		return nil, fmt.Errorf("read template ownership metadata %q: %w", manifestPath, err)
	}

	var manifest templateOwnershipManifest

	if err := json.Unmarshal(contents, &manifest); err != nil {
		return nil, fmt.Errorf("%w: decode template ownership metadata %q: %v", errTemplateOwnershipInvalid, manifestPath, err)
	}

	if err := validateTemplateOwnership(&manifest); err != nil {
		return nil, fmt.Errorf("%w: validate template ownership metadata %q: %v", errTemplateOwnershipInvalid, manifestPath, err)
	}

	return &manifest, nil
}

func validateTemplateOwnership(manifest *templateOwnershipManifest) error {
	if manifest.Version != templateOwnershipVersion {
		return fmt.Errorf("unsupported version %d", manifest.Version)
	}

	if manifest.Files == nil {
		return errors.New("files map is missing")
	}

	for relativePath, digest := range manifest.Files {
		if err := validateTemplateOwnershipPath(relativePath); err != nil {
			return err
		}

		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size || digest != strings.ToLower(digest) {
			return fmt.Errorf("path %q has an invalid SHA-256 digest", relativePath)
		}
	}

	return nil
}

func validateTemplateOwnershipPath(relativePath string) error {
	switch {
	case relativePath == "":
		return errors.New("template path is empty")
	case strings.ContainsRune(relativePath, '\x00'):
		return fmt.Errorf("path %q contains a NUL byte", relativePath)
	case strings.Contains(relativePath, `\`):
		return fmt.Errorf("path %q contains a non-portable separator", relativePath)
	case path.IsAbs(relativePath):
		return fmt.Errorf("path %q is absolute", relativePath)
	case filepath.VolumeName(filepath.FromSlash(relativePath)) != "" || len(relativePath) >= 2 && relativePath[1] == ':':
		return fmt.Errorf("path %q contains a volume name", relativePath)
	case relativePath == ".." || strings.HasPrefix(relativePath, "../"):
		return fmt.Errorf("path %q escapes the templates directory", relativePath)
	case path.Clean(relativePath) != relativePath:
		return fmt.Errorf("path %q is not normalized", relativePath)
	case !config.IsTemplate(relativePath):
		return fmt.Errorf("path %q is not a template", relativePath)
	default:
		return nil
	}
}

// cleanupRetiredTemplates removes unchanged templates retired by the current release.
// It returns ownership entries to retry after transient cleanup failures. Modified
// files and paths containing symlinks are preserved but deliberately relinquish
// installer ownership so later updates cannot delete user-controlled content.
func cleanupRetiredTemplates(dir string, previous, current *templateOwnershipManifest) (map[string]string, error) {
	retired := make(map[string]string)
	for relativePath, previousDigest := range previous.Files {
		if _, stillOwned := current.Files[relativePath]; !stillOwned {
			retired[relativePath] = previousDigest
		}
	}

	if len(retired) == 0 {
		return retired, nil
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return retired, fmt.Errorf("open templates directory %q for cleanup: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	currentPathsByFoldedName := make(map[string][]string, len(current.Files))
	for relativePath := range current.Files {
		foldedName := strings.ToLower(relativePath)
		currentPathsByFoldedName[foldedName] = append(currentPathsByFoldedName[foldedName], relativePath)
	}

	ownershipToRetry := make(map[string]string)
	var cleanupErr error
	for relativePath, previousDigest := range retired {
		templatePath := filepath.Join(dir, filepath.FromSlash(relativePath))
		quarantinePath := retiredTemplateQuarantinePath(relativePath)

		hasSymlink, err := templatePathHasSymlink(root, relativePath)
		if err != nil {
			if !os.IsNotExist(err) {
				ownershipToRetry[relativePath] = previousDigest
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("inspect retired template path %q: %w", templatePath, err))
			}

			continue
		}

		if hasSymlink {
			// gologger.Warning().Msgf("Preserving retired template path containing a symbolic link: %s", templatePath)
			continue
		}

		info, err := root.Stat(filepath.FromSlash(relativePath))
		if err != nil {
			if !os.IsNotExist(err) {
				ownershipToRetry[relativePath] = previousDigest
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("inspect retired template %q: %w", templatePath, err))
			}
			continue
		}

		if !info.Mode().IsRegular() {
			// gologger.Warning().Msgf("Preserving non-regular retired template path: %s", templatePath)
			continue
		}

		aliasesCurrentTemplate, err := retiredTemplateAliasesCurrent(root, relativePath, currentPathsByFoldedName)
		if err != nil {
			if !os.IsNotExist(err) {
				ownershipToRetry[relativePath] = previousDigest
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("compare retired template path %q with current templates: %w", templatePath, err))
			}
			continue
		}

		if aliasesCurrentTemplate {
			continue
		}

		if err := quarantineRetiredTemplate(root, filepath.FromSlash(relativePath), quarantinePath); err != nil {
			if !os.IsNotExist(err) {
				ownershipToRetry[relativePath] = previousDigest
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("quarantine retired template %q: %w", templatePath, err))
			}
			continue
		}

		disposition, err := cleanupQuarantinedTemplate(root, filepath.FromSlash(relativePath), quarantinePath, previousDigest)
		if disposition == retainTemplateOwnership {
			ownershipToRetry[relativePath] = previousDigest
		}

		if err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("clean up quarantined retired template %q: %w", templatePath, err))
		}
	}

	return ownershipToRetry, cleanupErr
}

func retiredTemplateQuarantinePath(relativePath string) string {
	digest := sha256.Sum256([]byte(relativePath))

	return templateOwnershipRetiredPrefix + hex.EncodeToString(digest[:])
}

func quarantineRetiredTemplate(root *os.Root, retiredPath, quarantinePath string) error {
	if err := root.Rename(retiredPath, quarantinePath); err != nil {
		return err
	}

	if err := syncTemplateOwnershipDirectory(root, "."); err != nil {
		return fmt.Errorf("sync quarantine directory after moving %q: %w", retiredPath, err)
	}

	parent := filepath.Dir(retiredPath)
	if parent != "." {
		if err := syncTemplateOwnershipDirectory(root, parent); err != nil {
			return fmt.Errorf("sync source directory %q after quarantining %q: %w", parent, retiredPath, err)
		}
	}

	return nil
}

type templateOwnershipDisposition uint8

const (
	relinquishTemplateOwnership templateOwnershipDisposition = iota
	retainTemplateOwnership
)

func cleanupQuarantinedTemplate(root *os.Root, retiredPath, quarantinePath, previousDigest string) (templateOwnershipDisposition, error) {
	info, err := root.Lstat(quarantinePath)
	if err != nil {
		restoreErr := restoreQuarantinedTemplate(root, retiredPath, quarantinePath)
		return retainTemplateOwnership, errors.Join(fmt.Errorf("inspect quarantine path %q: %w", quarantinePath, err), restoreErr)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		restoreErr := restoreQuarantinedTemplate(root, retiredPath, quarantinePath)
		if restoreErr != nil {
			return retainTemplateOwnership, restoreErr
		}

		// gologger.Warning().Msgf("Preserving retired template path containing a symbolic link: %s", retiredPath)

		return relinquishTemplateOwnership, nil
	}

	if !info.Mode().IsRegular() {
		restoreErr := restoreQuarantinedTemplate(root, retiredPath, quarantinePath)
		if restoreErr != nil {
			return retainTemplateOwnership, restoreErr
		}

		// gologger.Warning().Msgf("Preserving non-regular retired template path: %s", retiredPath)

		return relinquishTemplateOwnership, nil
	}

	contents, err := root.ReadFile(quarantinePath)
	if err != nil {
		restoreErr := restoreQuarantinedTemplate(root, retiredPath, quarantinePath)

		return retainTemplateOwnership, errors.Join(fmt.Errorf("read quarantine path %q: %w", quarantinePath, err), restoreErr)
	}

	if templateDigest(contents) != previousDigest {
		restoreErr := restoreQuarantinedTemplate(root, retiredPath, quarantinePath)
		if restoreErr != nil {
			return retainTemplateOwnership, restoreErr
		}

		// gologger.Warning().Msgf("Preserving locally modified retired template: %s", retiredPath)

		return relinquishTemplateOwnership, nil
	}

	if err := root.Remove(quarantinePath); err != nil {
		restoreErr := restoreQuarantinedTemplate(root, retiredPath, quarantinePath)
		return retainTemplateOwnership, errors.Join(fmt.Errorf("remove quarantine path %q: %w", quarantinePath, err), restoreErr)
	}

	if err := syncTemplateOwnershipDirectory(root, "."); err != nil {
		return retainTemplateOwnership, fmt.Errorf("sync quarantine directory after removing %q: %w", quarantinePath, err)
	}

	if _, err := root.Lstat(retiredPath); err == nil {
		return retainTemplateOwnership, nil
	} else if !os.IsNotExist(err) {
		return retainTemplateOwnership, fmt.Errorf("inspect restored retired template %q: %w", retiredPath, err)
	}

	return relinquishTemplateOwnership, nil
}

func restoreQuarantinedTemplate(root *os.Root, retiredPath, quarantinePath string) error {
	return restoreQuarantinedTemplateWithLink(root, retiredPath, quarantinePath, root.Link)
}

func restoreQuarantinedTemplateWithLink(root *os.Root, retiredPath, quarantinePath string, link func(string, string) error) error {
	parent := filepath.Dir(retiredPath)
	if parent != "." {
		parentsToSync, err := createTemplateDirectories(root, parent)
		if err != nil {
			return fmt.Errorf("recreate parent directory %q for retired template %q: %w", parent, retiredPath, err)
		}
		for _, parentToSync := range parentsToSync {
			if err := syncTemplateOwnershipDirectory(root, parentToSync); err != nil {
				return fmt.Errorf("sync recreated directory parent %q: %w", parentToSync, err)
			}
		}
	}

	completed, err := finishInterruptedTemplateRestore(root, retiredPath, quarantinePath, syncTemplateOwnershipFile)
	if err != nil {
		return err
	}
	if completed {
		return nil
	}

	if err := link(quarantinePath, retiredPath); err == nil {
		return commitQuarantinedTemplateRestore(root, retiredPath, quarantinePath)
	} else if os.IsExist(err) {
		return fmt.Errorf("restore retired template %q; quarantined contents remain at %q: %w", retiredPath, quarantinePath, err)
	}

	moveErr := moveQuarantinedTemplate(root, retiredPath, quarantinePath)
	if moveErr == nil {
		return nil
	}

	if os.IsExist(moveErr) {
		return fmt.Errorf("restore retired template %q; quarantined contents remain at %q: %w", retiredPath, quarantinePath, moveErr)
	}

	if copyErr := copyQuarantinedTemplateWithLink(root, retiredPath, quarantinePath, link); copyErr != nil {
		return errors.Join(moveErr, copyErr)
	}

	return nil
}

func moveQuarantinedTemplate(root *os.Root, retiredPath, quarantinePath string) error {
	state, err := newTemplateRestoreState(retiredPath)
	if err != nil {
		return err
	}

	contents, err := root.ReadFile(quarantinePath)
	if err != nil {
		return fmt.Errorf("read quarantined template %q before moving: %w", quarantinePath, err)
	}

	state.digest = templateDigest(contents)
	state.kind = templateRestoreMove

	if err := createTemplateRestoreState(root, state); err != nil {
		return err
	}

	if err := relocateTemplateRestoreNoReplace(root, quarantinePath, retiredPath); err != nil {
		return errors.Join(err, cleanupTemplateRestoreState(root, state))
	}

	return cleanupTemplateRestoreState(root, state)
}

func createTemplateDirectories(root *os.Root, parent string) ([]string, error) {
	current := ""
	var parentsToSync []string

	for _, component := range strings.Split(filepath.Clean(parent), string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		parentsToSync = append(parentsToSync, filepath.Dir(current))
		info, err := root.Lstat(current)
		if err == nil {
			if !info.IsDir() {
				return nil, fmt.Errorf("template parent path %q is not a directory", current)
			}
			continue
		}

		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("inspect template parent path %q: %w", current, err)
		}

	}

	if err := root.MkdirAll(parent, 0o755); err != nil {
		return parentsToSync, err
	}

	return parentsToSync, nil
}

func finishInterruptedTemplateRestore(root *os.Root, retiredPath, quarantinePath string, syncFile func(*os.Root, string, fs.FileMode) error) (bool, error) {
	retiredInfo, err := root.Lstat(retiredPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}

		return false, fmt.Errorf("inspect restored retired template %q: %w", retiredPath, err)
	}

	quarantineInfo, err := root.Lstat(quarantinePath)
	if err != nil {
		return false, fmt.Errorf("inspect quarantine path %q for completed restore: %w", quarantinePath, err)
	}
	if !retiredInfo.Mode().IsRegular() || !quarantineInfo.Mode().IsRegular() {
		return false, nil
	}

	sameFile := os.SameFile(retiredInfo, quarantineInfo)
	identical := sameFile

	var restoreState templateRestoreState

	if !identical {
		var found bool

		restoreState, found, err = findTemplateRestoreState(root, retiredPath)
		if err != nil {
			return false, err
		}

		if !found || retiredInfo.Mode().Perm() != quarantineInfo.Mode().Perm() {
			return false, nil
		}

		temporaryInfo, err := root.Lstat(restoreState.temporaryPath)
		if err == nil && (!temporaryInfo.Mode().IsRegular() || !os.SameFile(retiredInfo, temporaryInfo)) {
			return false, nil
		}

		if err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("inspect temporary restored template %q: %w", restoreState.temporaryPath, err)
		}

		retiredContents, err := root.ReadFile(retiredPath)
		if err != nil {
			return false, fmt.Errorf("read restored retired template %q: %w", retiredPath, err)
		}

		quarantinedContents, err := root.ReadFile(quarantinePath)
		if err != nil {
			return false, fmt.Errorf("read quarantine path %q for completed restore: %w", quarantinePath, err)
		}

		identical = bytes.Equal(retiredContents, quarantinedContents)
	}

	if !identical {
		return false, nil
	}

	if !sameFile {
		if err := syncFile(root, retiredPath, quarantineInfo.Mode().Perm()); err != nil {
			return false, fmt.Errorf("sync copied restored template %q: %w", retiredPath, err)
		}
	}

	if err := commitQuarantinedTemplateRestore(root, retiredPath, quarantinePath); err != nil {
		return false, err
	}

	if !sameFile {
		if err := cleanupTemplateRestoreState(root, restoreState); err != nil {
			return false, err
		}
	}

	return true, nil
}

func commitQuarantinedTemplateRestore(root *os.Root, retiredPath, quarantinePath string) error {
	parent := filepath.Dir(retiredPath)
	if err := syncTemplateOwnershipDirectory(root, parent); err != nil {
		return fmt.Errorf("sync restored template directory %q: %w", parent, err)
	}

	if err := root.Remove(quarantinePath); err != nil {
		return fmt.Errorf("remove restored quarantine path %q: %w", quarantinePath, err)
	}

	if err := syncTemplateOwnershipDirectory(root, "."); err != nil {
		return fmt.Errorf("sync quarantine directory after removing %q: %w", quarantinePath, err)
	}

	return nil
}

func copyQuarantinedTemplate(root *os.Root, retiredPath, quarantinePath string) error {
	return copyQuarantinedTemplateWithLink(root, retiredPath, quarantinePath, root.Link)
}

func copyQuarantinedTemplateWithLink(root *os.Root, retiredPath, quarantinePath string, link func(string, string) error) error {
	quarantined, err := root.Open(quarantinePath)
	if err != nil {
		return fmt.Errorf("open quarantined template %q for restore: %w", quarantinePath, err)
	}
	defer func() { _ = quarantined.Close() }()

	info, err := quarantined.Stat()
	if err != nil {
		return fmt.Errorf("inspect quarantined template %q for restore: %w", quarantinePath, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("restore retired template %q; non-regular quarantined contents remain at %q", retiredPath, quarantinePath)
	}

	restoreState, err := newTemplateRestoreState(retiredPath)
	if err != nil {
		return err
	}

	restored, err := root.OpenFile(restoreState.temporaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary restored template %q; quarantined contents remain at %q: %w", restoreState.temporaryPath, quarantinePath, err)
	}

	published := false
	defer func() {
		_ = restored.Close()
		if !published {
			_ = root.Remove(restoreState.temporaryPath)
		}
	}()

	digest := sha256.New()
	if _, err := io.Copy(io.MultiWriter(restored, digest), quarantined); err != nil {
		return fmt.Errorf("restore retired template %q from %q: %w", retiredPath, quarantinePath, err)
	}

	restoreState.digest = hex.EncodeToString(digest.Sum(nil))
	restoreState.kind = templateRestoreCopy

	if err := restored.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("restore permissions on retired template %q: %w", retiredPath, err)
	}

	if err := restored.Sync(); err != nil {
		return fmt.Errorf("sync restored retired template %q: %w", retiredPath, err)
	}

	if err := restored.Close(); err != nil {
		return fmt.Errorf("close restored retired template %q: %w", retiredPath, err)
	}

	if err := createTemplateRestoreState(root, restoreState); err != nil {
		return err
	}

	if err := publishTemplateRestore(root, restoreState.temporaryPath, retiredPath, link); err != nil {
		cleanupErr := cleanupTemplateRestoreState(root, restoreState)
		return errors.Join(fmt.Errorf("publish restored retired template %q without overwriting; quarantined contents remain at %q: %w", retiredPath, quarantinePath, err), cleanupErr)
	}

	published = true

	if err := verifyCopiedTemplateRestore(root, retiredPath, quarantinePath, info.Mode()); err != nil {
		return err
	}

	if err := commitQuarantinedTemplateRestore(root, retiredPath, quarantinePath); err != nil {
		return err
	}

	return cleanupTemplateRestoreState(root, restoreState)
}

func verifyCopiedTemplateRestore(root *os.Root, retiredPath, quarantinePath string, mode fs.FileMode) error {
	restoredInfo, err := root.Stat(retiredPath)
	if err != nil {
		return fmt.Errorf("inspect copied restored template %q: %w", retiredPath, err)
	}

	quarantineInfo, err := root.Stat(quarantinePath)
	if err != nil {
		return fmt.Errorf("inspect quarantine after copying %q: %w", quarantinePath, err)
	}

	if restoredInfo.Mode().Perm() != mode.Perm() || quarantineInfo.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("quarantined template %q changed permissions while being restored", quarantinePath)
	}

	restoredContents, err := root.ReadFile(retiredPath)
	if err != nil {
		return fmt.Errorf("read copied restored template %q: %w", retiredPath, err)
	}

	quarantinedContents, err := root.ReadFile(quarantinePath)
	if err != nil {
		return fmt.Errorf("read quarantine after copying %q: %w", quarantinePath, err)
	}

	if !bytes.Equal(restoredContents, quarantinedContents) {
		return fmt.Errorf("quarantined template %q changed while being restored", quarantinePath)
	}

	return nil
}

func publishTemplateRestore(root *os.Root, temporaryPath, retiredPath string, link func(string, string) error) error {
	if err := link(temporaryPath, retiredPath); err == nil {
		return nil
	} else if os.IsExist(err) {
		return err
	}

	return relocateTemplateRestoreNoReplace(root, temporaryPath, retiredPath)
}

// relocateTemplateRestoreNoReplace moves source to destination without
// overwriting. When the platform rename flag is unsupported, it falls back to
// an O_CREATE|O_EXCL create-and-copy so restores still succeed on filesystems
// that reject RENAME_NOREPLACE / RENAME_EXCL.
func relocateTemplateRestoreNoReplace(root *os.Root, sourcePath, destinationPath string) error {
	err := renameTemplateRestoreNoReplaceFn(root, sourcePath, destinationPath)
	if err == nil || os.IsExist(err) || !errors.Is(err, errors.ErrUnsupported) {
		return err
	}

	return exclusivePublishTemplateRestore(root, sourcePath, destinationPath)
}

// renameTemplateRestoreNoReplaceFn is the platform exclusive-rename implementation.
// Tests may override it to exercise the unsupported-flag fallback.
var renameTemplateRestoreNoReplaceFn = renameTemplateRestoreNoReplace

func exclusivePublishTemplateRestore(root *os.Root, sourcePath, destinationPath string) error {
	source, err := root.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open restore source %q: %w", sourcePath, err)
	}
	defer func() { _ = source.Close() }()

	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("inspect restore source %q: %w", sourcePath, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("restore source %q is not a regular file", sourcePath)
	}

	destination, err := root.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive restore destination %q: %w", destinationPath, err)
	}

	published := false
	defer func() {
		_ = destination.Close()
		if !published {
			_ = root.Remove(destinationPath)
		}
	}()

	if _, err := io.Copy(destination, source); err != nil {
		return fmt.Errorf("copy restore source %q to %q: %w", sourcePath, destinationPath, err)
	}
	if err := destination.Chmod(info.Mode().Perm()); err != nil {
		return fmt.Errorf("restore permissions on %q: %w", destinationPath, err)
	}
	if err := destination.Sync(); err != nil {
		return fmt.Errorf("sync exclusive restore destination %q: %w", destinationPath, err)
	}
	if err := destination.Close(); err != nil {
		return fmt.Errorf("close exclusive restore destination %q: %w", destinationPath, err)
	}

	if err := root.Remove(sourcePath); err != nil {
		return fmt.Errorf("remove restore source %q after exclusive publish: %w", sourcePath, err)
	}

	published = true
	return nil
}

func templateRestoreTemporaryPath(retiredPath string) string {
	digest := sha256.Sum256([]byte(filepath.ToSlash(retiredPath)))

	return filepath.Join(filepath.Dir(retiredPath), templateOutputTemporaryPrefix+hex.EncodeToString(digest[:16]))
}

func templateRestoreStatePrefix(retiredPath string) string {
	digest := sha256.Sum256([]byte(filepath.ToSlash(retiredPath)))

	return templateOwnershipRestorePrefix + hex.EncodeToString(digest[:]) + "-"
}

func newTemplateRestoreState(retiredPath string) (templateRestoreState, error) {
	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return templateRestoreState{}, fmt.Errorf("generate temporary restore name: %w", err)
	}

	token := hex.EncodeToString(randomSuffix)
	return templateRestoreState{
		retiredPath:   retiredPath,
		temporaryPath: templateRestoreTemporaryPath(retiredPath) + "-" + token,
		statePath:     templateRestoreStatePrefix(retiredPath) + token,
	}, nil
}

func createTemplateRestoreState(root *os.Root, state templateRestoreState) error {
	if state.kind != templateRestoreCopy && state.kind != templateRestoreMove {
		return fmt.Errorf("template restore state %q has an invalid kind", state.statePath)
	}

	if !isLowerHex(state.digest, sha256.Size*2) {
		return fmt.Errorf("template restore state %q has an invalid digest", state.statePath)
	}

	stateFile, err := root.OpenFile(state.statePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create template restore state %q: %w", state.statePath, err)
	}

	_, writeErr := stateFile.Write([]byte(string(state.kind) + "\n" + state.digest))
	syncErr := stateFile.Sync()
	closeErr := stateFile.Close()

	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = root.Remove(state.statePath)

		return fmt.Errorf("persist template restore state %q: %w", state.statePath, err)
	}

	if err := syncTemplateOwnershipDirectory(root, "."); err != nil {
		return fmt.Errorf("sync template restore state %q: %w", state.statePath, err)
	}

	return nil
}

func findTemplateRestoreState(root *os.Root, retiredPath string) (templateRestoreState, bool, error) {
	directory, err := root.Open(".")
	if err != nil {
		return templateRestoreState{}, false, fmt.Errorf("open templates directory for restore state: %w", err)
	}

	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()

	if err := errors.Join(readErr, closeErr); err != nil {
		return templateRestoreState{}, false, fmt.Errorf("inspect templates directory for restore state: %w", err)
	}

	prefix := templateRestoreStatePrefix(retiredPath)

	var found templateRestoreState

	for _, entry := range entries {
		token, ok := strings.CutPrefix(entry.Name(), prefix)
		if !ok || !isLowerHex(token, 32) {
			continue
		}

		if found.statePath != "" {
			return templateRestoreState{}, false, fmt.Errorf("multiple template restore states for %q", retiredPath)
		}

		found = templateRestoreState{
			retiredPath:   retiredPath,
			temporaryPath: templateRestoreTemporaryPath(retiredPath) + "-" + token,
			statePath:     entry.Name(),
		}
	}

	if found.statePath == "" {
		return found, false, nil
	}

	if err := loadTemplateRestoreState(root, &found); err != nil {
		return templateRestoreState{}, false, err
	}

	return found, true, nil
}

func loadTemplateRestoreState(root *os.Root, state *templateRestoreState) error {
	info, err := root.Lstat(state.statePath)
	if err != nil {
		return fmt.Errorf("inspect template restore state %q: %w", state.statePath, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("template restore state %q is not a regular file", state.statePath)
	}

	stateFile, err := root.Open(state.statePath)
	if err != nil {
		return fmt.Errorf("open template restore state %q: %w", state.statePath, err)
	}

	contents, readErr := io.ReadAll(io.LimitReader(stateFile, 70))
	closeErr := stateFile.Close()

	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("read template restore state %q: %w", state.statePath, err)
	}

	kind, digest, found := strings.Cut(string(contents), "\n")
	if !found {
		return fmt.Errorf("template restore state %q is malformed", state.statePath)
	}

	state.kind = templateRestoreKind(kind)
	state.digest = digest

	if state.kind != templateRestoreCopy && state.kind != templateRestoreMove {
		return fmt.Errorf("template restore state %q has an invalid kind", state.statePath)
	}

	if !isLowerHex(state.digest, sha256.Size*2) {
		return fmt.Errorf("template restore state %q has an invalid digest", state.statePath)
	}

	return nil
}

func cleanupCommittedTemplateRestore(root *os.Root, state templateRestoreState) error {
	retiredInfo, err := root.Lstat(state.retiredPath)
	if err != nil {
		return fmt.Errorf("inspect committed restored template %q: %w", state.retiredPath, err)
	}

	if !retiredInfo.Mode().IsRegular() {
		return fmt.Errorf("committed restored template %q is not a regular file", state.retiredPath)
	}

	if state.kind == templateRestoreMove {
		return cleanupTemplateRestoreState(root, state)
	}

	temporaryInfo, err := root.Lstat(state.temporaryPath)
	if err == nil && (!temporaryInfo.Mode().IsRegular() || !os.SameFile(retiredInfo, temporaryInfo)) {
		return fmt.Errorf("temporary restore state %q does not identify restored template %q", state.statePath, state.retiredPath)
	}

	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect temporary restored template %q: %w", state.temporaryPath, err)
	}

	if os.IsNotExist(err) {
		matches, err := templateRestoreFileMatchesDigest(root, state.retiredPath, state.digest)
		if err != nil {
			return err
		}

		if !matches {
			return fmt.Errorf("restore state %q does not identify restored template %q", state.statePath, state.retiredPath)
		}
	}

	return cleanupTemplateRestoreState(root, state)
}

func rollbackTemplateRestoreState(root *os.Root, state templateRestoreState) error {
	if state.kind != templateRestoreCopy {
		return fmt.Errorf("restore state %q does not own a copied destination", state.statePath)
	}

	retiredInfo, err := root.Lstat(state.retiredPath)
	if err != nil {
		return fmt.Errorf("inspect stale restored template %q: %w", state.retiredPath, err)
	}

	temporaryInfo, temporaryErr := root.Lstat(state.temporaryPath)
	if temporaryErr == nil {
		if !temporaryInfo.Mode().IsRegular() || !os.SameFile(retiredInfo, temporaryInfo) {
			return fmt.Errorf("restore state %q does not own stale destination %q", state.statePath, state.retiredPath)
		}
	} else if os.IsNotExist(temporaryErr) {
		// A no-replace rename consumes the temporary path; the persisted digest
		// below proves the destination still contains that published copy.
	} else {
		return fmt.Errorf("inspect temporary restored template %q: %w", state.temporaryPath, temporaryErr)
	}

	matches, err := templateRestoreFileMatchesDigest(root, state.retiredPath, state.digest)
	if err != nil {
		return err
	}

	if !matches {
		return fmt.Errorf("restore state %q does not own replacement %q", state.statePath, state.retiredPath)
	}

	if err := root.Remove(state.retiredPath); err != nil {
		return fmt.Errorf("remove stale restored template %q: %w", state.retiredPath, err)
	}

	if err := syncTemplateOwnershipDirectory(root, filepath.Dir(state.retiredPath)); err != nil {
		return fmt.Errorf("sync restored template directory after rollback: %w", err)
	}

	return cleanupTemplateRestoreState(root, state)
}

func templateRestoreFileMatchesDigest(root *os.Root, relativePath, digest string) (bool, error) {
	contents, err := root.ReadFile(relativePath)
	if err != nil {
		return false, fmt.Errorf("read restored template %q: %w", relativePath, err)
	}

	return templateDigest(contents) == digest, nil
}

func cleanupTemplateRestoreState(root *os.Root, state templateRestoreState) error {
	if state.kind == templateRestoreCopy {
		if err := removeRegularTemplateRestoreFile(root, state.temporaryPath); err != nil {
			return err
		}
	}

	if err := syncTemplateOwnershipDirectory(root, filepath.Dir(state.temporaryPath)); err != nil {
		return fmt.Errorf("sync restored template directory %q after temporary cleanup: %w", filepath.Dir(state.temporaryPath), err)
	}

	if err := removeRegularTemplateRestoreFile(root, state.statePath); err != nil {
		return err
	}

	if err := syncTemplateOwnershipDirectory(root, "."); err != nil {
		return fmt.Errorf("sync templates directory after restore-state cleanup: %w", err)
	}

	return nil
}

func removeRegularTemplateRestoreFile(root *os.Root, relativePath string) error {
	info, err := root.Lstat(relativePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return fmt.Errorf("inspect template restore file %q: %w", relativePath, err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("template restore file %q is not a regular file", relativePath)
	}

	if err := root.Remove(relativePath); err != nil {
		return fmt.Errorf("remove template restore file %q: %w", relativePath, err)
	}

	return nil
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}

	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}

	return true
}

func retiredTemplateAliasesCurrent(root *os.Root, retiredPath string, currentPathsByFoldedName map[string][]string) (bool, error) {
	candidates := currentPathsByFoldedName[strings.ToLower(retiredPath)]
	if len(candidates) == 0 {
		return false, nil
	}

	retiredInfo, err := root.Stat(filepath.FromSlash(retiredPath))
	if err != nil {
		return false, err
	}

	for _, currentPath := range candidates {
		currentInfo, err := root.Stat(filepath.FromSlash(currentPath))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, err
		}

		if os.SameFile(retiredInfo, currentInfo) {
			return true, nil
		}
	}

	return false, nil
}

func writeTemplateOwnership(dir string, manifest *templateOwnershipManifest) error {
	if err := validateTemplateOwnership(manifest); err != nil {
		return fmt.Errorf("validate template ownership metadata: %w", err)
	}

	contents, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode template ownership metadata: %w", err)
	}

	contents = append(contents, '\n')
	manifestPath := filepath.Join(dir, templateOwnershipFileName)

	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open templates directory %q: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	if info, err := root.Lstat(templateOwnershipFileName); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("template ownership metadata %q is a symbolic link", manifestPath)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect template ownership metadata %q: %w", manifestPath, err)
	}

	temporary, err := os.CreateTemp(dir, templateOwnershipTemporaryPrefix+"*")
	if err != nil {
		return fmt.Errorf("create temporary template ownership metadata in %q: %w", dir, err)
	}

	temporaryName := filepath.Base(temporary.Name())

	defer func() {
		_ = temporary.Close()
		_ = root.Remove(temporaryName)
	}()

	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write temporary template ownership metadata %q: %w", temporary.Name(), err)
	}

	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary template ownership metadata %q: %w", temporary.Name(), err)
	}

	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary template ownership metadata %q: %w", temporary.Name(), err)
	}

	if err := root.Rename(temporaryName, templateOwnershipFileName); err != nil {
		return fmt.Errorf("replace template ownership metadata %q: %w", manifestPath, err)
	}

	if err := syncTemplateOwnershipDirectory(root, "."); err != nil {
		return fmt.Errorf("sync templates directory %q after ownership update: %w", dir, err)
	}

	return nil
}

func templatePathHasSymlink(root *os.Root, relativePath string) (bool, error) {
	currentPath := ""
	for _, component := range strings.Split(filepath.FromSlash(relativePath), string(os.PathSeparator)) {
		currentPath = filepath.Join(currentPath, component)

		info, err := root.Lstat(currentPath)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}

			return false, err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return true, nil
		}
	}

	return false, nil
}
