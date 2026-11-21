package nuclei

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/pkg/errors"                                       //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/types"             //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	fileutil "github.com/projectdiscovery/utils/file"             //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	permissionutil "github.com/projectdiscovery/utils/permission" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
)

// loadResumeCfg returns the scan progression stored in the file set by
// WithResumeFile, or an empty one when the file does not exist yet. It mirrors
// what the CLI runner does for -resume. The thread-safe engine ignores the file,
// so a malformed one must not stop it from starting.
func (e *NucleiEngine) loadResumeCfg() (*types.ResumeCfg, error) {
	resumeCfg := types.NewResumeCfg()
	if e.mode == threadSafe || !e.opts.ShouldLoadResume() {
		return resumeCfg, nil
	}

	data, err := os.ReadFile(e.opts.Resume)
	if err != nil {
		return nil, errors.Wrap(err, "could not read resume file")
	}

	err = json.Unmarshal(data, resumeCfg)
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse resume file %q", e.opts.Resume)
	}

	resumeCfg.Compile()

	return resumeCfg, nil
}

// resetResumeProgress drops the progress that earlier calls on this engine
// recorded. Each call then starts like a new CLI run with -resume: it skips what
// the loaded file marks as done and saves only what it did itself. Without it, a
// template that an earlier call finished stays completed in the next call's
// saved file, and resuming from that file skips work the call never finished.
func (e *NucleiEngine) resetResumeProgress() {
	resumeCfg := e.executerOpts.ResumeCfg

	resumeCfg.Lock()
	defer resumeCfg.Unlock()

	resumeCfg.Current = make(map[string]*types.ResumeInfo)
}

// saveResumeCfg writes the scan progression to the file set by WithResumeFile.
// It mirrors Runner.SaveResumeConfig, which the CLI calls on interrupt.
func (e *NucleiEngine) saveResumeCfg() error {
	path := e.opts.Resume

	dir := filepath.Dir(path)
	if !fileutil.FolderExists(dir) {
		err := os.MkdirAll(dir, permissionutil.ConfigFolderPermission)
		if err != nil {
			return errors.Wrapf(err, "could not create resume directory %q", dir)
		}
	}

	resumeCfg := e.executerOpts.ResumeCfg.Clone()
	resumeCfg.ResumeFrom = resumeCfg.Current

	data, err := json.MarshalIndent(resumeCfg, "", "\t")
	if err != nil {
		return errors.Wrap(err, "could not encode resume configuration")
	}

	err = os.WriteFile(path, data, permissionutil.ConfigFilePermission)
	if err != nil {
		return errors.Wrapf(err, "could not write resume file %q", path)
	}

	return nil
}
