package configuration

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/projectdiscovery/goflags"
	catalogconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestConfigurationPrecedence(t *testing.T) {
	dir := t.TempDir()
	preferredSystemDir := filepath.Join(dir, "preferred-system")
	fallbackSystemDir := filepath.Join(dir, "fallback-system")
	preferredSystemPath := filepath.Join(preferredSystemDir, catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	fallbackSystemPath := filepath.Join(fallbackSystemDir, catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	unixSystemPath := filepath.Join(dir, "etc", catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	userPath := filepath.Join(dir, "user.yaml")
	explicitPath := filepath.Join(dir, "explicit.yaml")
	profilePath := filepath.Join(dir, "profile.yaml")

	writeConfigFile(t, fallbackSystemPath, `
fallback-only: fallback
preferred-wins: fallback
local-wins: fallback
user-wins: fallback
explicit-wins: fallback
profile-wins: fallback
cli-wins: fallback
default-wins: fallback
config: ignored.yaml
profile: ignored.yaml
`)
	writeConfigFile(t, preferredSystemPath, `
preferred-wins: preferred
local-wins: preferred
user-wins: preferred
explicit-wins: preferred
profile-wins: preferred
cli-wins: preferred
default-wins: preferred
`)
	writeConfigFile(t, unixSystemPath, `
local-wins: local
user-wins: local
explicit-wins: local
profile-wins: local
cli-wins: local
default-wins: local
`)
	writeConfigFile(t, userPath, fmt.Sprintf(`
user-wins: user
explicit-wins: user
profile-wins: user
cli-wins: user
default-wins: user
config: %q
profile: ignored-user.yaml
`, explicitPath))
	writeConfigFile(t, explicitPath, fmt.Sprintf(`
explicit-wins: explicit
profile-wins: explicit
cli-wins: explicit
default-wins: explicit
profile: %q
`, profilePath))
	writeConfigFile(t, profilePath, `
profile-wins: profile
cli-wins: profile
default-wins: profile
`)

	var fallbackOnly, preferredWins, localWins, userWins, explicitWins, profileWins, cliWins, defaultWins string
	var selected Selection
	flagSet := goflags.NewFlagSet()
	flagSet.StringVar(&fallbackOnly, "fallback-only", "built-in", "")
	flagSet.StringVar(&preferredWins, "preferred-wins", "built-in", "")
	flagSet.StringVar(&localWins, "local-wins", "built-in", "")
	flagSet.StringVar(&userWins, "user-wins", "built-in", "")
	flagSet.StringVar(&explicitWins, "explicit-wins", "built-in", "")
	flagSet.StringVar(&profileWins, "profile-wins", "built-in", "")
	flagSet.StringVar(&cliWins, "cli-wins", "built-in", "")
	flagSet.StringVar(&defaultWins, "default-wins", "built-in", "")
	flagSet.StringVar(&selected.Config, "config", "", "")
	flagSet.StringVar(&selected.Profile, "profile", "", "")

	automaticFiles := []string{fallbackSystemPath, preferredSystemPath, unixSystemPath, userPath}
	automaticErr, err := loadTestFlags(flagSet, automaticFiles, &selected, existingProfilePath, "-cli-wins=cli", "-default-wins=built-in")
	if err != nil {
		t.Fatalf("load configuration failed: %v", err)
	}
	if automaticErr != nil {
		t.Fatalf("automatic configuration failed: %v", automaticErr)
	}

	assertEqual(t, "fallback-only", fallbackOnly, "fallback")
	assertEqual(t, "preferred-wins", preferredWins, "preferred")
	assertEqual(t, "local-wins", localWins, "local")
	assertEqual(t, "user-wins", userWins, "user")
	assertEqual(t, "explicit-wins", explicitWins, "explicit")
	assertEqual(t, "profile-wins", profileWins, "profile")
	assertEqual(t, "cli-wins", cliWins, "cli")
	assertEqual(t, "default-wins", defaultWins, "built-in")
	assertEqual(t, "selected config", selected.Config, explicitPath)
	assertEqual(t, "selected profile", selected.Profile, profilePath)
}

func TestAutomaticConfigFiles(t *testing.T) {
	dir := t.TempDir()
	preferredSystemDir := filepath.Join(dir, "preferred")
	fallbackSystemDir := filepath.Join(dir, "fallback")
	userConfigDir := filepath.Join(dir, "user")
	preferredSystemFile := filepath.Join(preferredSystemDir, catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	fallbackSystemFile := filepath.Join(fallbackSystemDir, catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	userConfigFile := filepath.Join(userConfigDir, catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	unixSystemFile := unixSystemConfigFilePath("linux")

	got := automaticConfigFiles([]string{preferredSystemDir, "relative-system", fallbackSystemDir}, "linux", userConfigFile)
	want := []string{
		fallbackSystemFile,
		preferredSystemFile,
		unixSystemFile,
		userConfigFile,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("automatic config files = %v, want %v", got, want)
	}

	got = automaticConfigFiles([]string{preferredSystemDir, "/etc", userConfigDir}, "linux", userConfigFile)
	want = []string{
		preferredSystemFile,
		unixSystemFile,
		userConfigFile,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("automatic config files with duplicate system paths = %v, want %v", got, want)
	}

	got = automaticConfigFiles([]string{preferredSystemDir, "/etc"}, "linux", unixSystemFile)
	want = []string{
		preferredSystemFile,
		unixSystemFile,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("automatic config files with Unix path used as user path = %v, want %v", got, want)
	}
}

func TestHigherPriorityFilesReplaceCollections(t *testing.T) {
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "system.yaml")
	userPath := filepath.Join(dir, "user.yaml")
	explicitPath := filepath.Join(dir, "explicit.yaml")
	profilePath := filepath.Join(dir, "profile.yaml")

	writeConfigFile(t, systemPath, "replace: [system-a, system-b]\nclear: [system]\nvar: [system=one]\n")
	writeConfigFile(t, userPath, fmt.Sprintf("replace: [user]\nclear: [user]\nvar: [user=two]\nconfig: %q\n", explicitPath))
	writeConfigFile(t, explicitPath, fmt.Sprintf("replace: [explicit-a, explicit-b]\nclear: [explicit]\nvar: [explicit=three]\nprofile: %q\n", profilePath))
	writeConfigFile(t, profilePath, "replace: [profile]\nclear: []\nvar: [profile=four]\n")

	var replace, clear goflags.StringSlice
	var variables goflags.RuntimeMap
	var selected Selection
	flagSet := goflags.NewFlagSet()
	flagSet.StringSliceVar(&replace, "replace", nil, "", goflags.StringSliceOptions)
	flagSet.StringSliceVar(&clear, "clear", nil, "", goflags.StringSliceOptions)
	flagSet.RuntimeMapVar(&variables, "var", nil, "")
	flagSet.StringVar(&selected.Config, "config", "", "")
	flagSet.StringVar(&selected.Profile, "profile", "", "")

	automaticErr, err := loadTestFlags(flagSet, []string{systemPath, userPath}, &selected, existingProfilePath, "-config="+explicitPath)
	if err != nil {
		t.Fatalf("load configuration failed: %v", err)
	}
	if automaticErr != nil {
		t.Fatalf("automatic configuration failed: %v", automaticErr)
	}
	if !slices.Equal(replace, []string{"profile"}) {
		t.Fatalf("replace = %v, want [profile]", replace)
	}
	if len(clear) != 0 {
		t.Fatalf("clear = %v, want an empty list", clear)
	}
	if got := variables.AsMap(); len(got) != 1 || got["profile"] != "four" {
		t.Fatalf("var = %v, want only profile=four", got)
	}
}

func TestParsingCreatesPrimaryUserConfig(t *testing.T) {
	tests := []struct {
		name         string
		createSystem bool
		wantValue    string
		forbidInUser string
	}{
		{name: "missing system", wantValue: "built-in"},
		{name: "system values are not materialized", createSystem: true, wantValue: "system", forbidInUser: "system"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			systemPath := filepath.Join(dir, "system.yaml")
			userPath := filepath.Join(dir, "user", "yaml")
			if test.createSystem {
				writeConfigFile(t, systemPath, "value: system\n")
			}

			value := "built-in"
			var selected Selection
			var noop bool
			flagSet := goflags.NewFlagSet()
			flagSet.StringVar(&value, "value", "built-in", "value description")
			flagSet.StringVar(&selected.Config, "config", "", "")
			flagSet.StringVar(&selected.Profile, "profile", "", "")
			flagSet.BoolVar(&noop, "noop", false, "")

			automaticErr, err := loadTestFlags(flagSet, []string{systemPath, userPath}, &selected, existingProfilePath, "-noop=false")
			if err != nil {
				t.Fatalf("load configuration failed: %v", err)
			}
			if automaticErr != nil {
				t.Fatalf("automatic configuration failed: %v", automaticErr)
			}
			assertEqual(t, "value", value, test.wantValue)

			data, err := os.ReadFile(userPath)
			if err != nil {
				t.Fatalf("read generated user config: %v", err)
			}
			content := string(data)
			if !strings.Contains(content, "#value: built-in") {
				t.Fatalf("generated user config is not a commented built-in config:\n%s", content)
			}
			if test.forbidInUser != "" && strings.Contains(content, test.forbidInUser) {
				t.Fatalf("generated user config materialized %q:\n%s", test.forbidInUser, content)
			}
		})
	}
}

func TestSelectedConfigLoadsAfterMalformedAutomaticConfig(t *testing.T) {
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "system.yaml")
	userPath := filepath.Join(dir, "user.yaml")
	explicitPath := filepath.Join(dir, "explicit.yaml")
	writeConfigFile(t, systemPath, "value: system\nautomatic-only: system\n")
	writeConfigFile(t, userPath, "value: [\n")
	writeConfigFile(t, explicitPath, "value: explicit\n")

	value := "built-in"
	automaticOnly := "built-in"
	var selected Selection
	flagSet := goflags.NewFlagSet()
	flagSet.StringVar(&value, "value", "built-in", "")
	flagSet.StringVar(&automaticOnly, "automatic-only", "built-in", "")
	flagSet.StringVar(&selected.Config, "config", "", "")
	flagSet.StringVar(&selected.Profile, "profile", "", "")

	automaticErr, err := loadTestFlags(flagSet, []string{systemPath, userPath}, &selected, existingProfilePath, "-config="+explicitPath)
	if err != nil {
		t.Fatalf("valid explicit config failed after malformed automatic config: %v", err)
	}
	if automaticErr == nil {
		t.Fatal("expected malformed automatic configuration error")
	}
	assertEqual(t, "value", value, "explicit")
	assertEqual(t, "automatic-only", automaticOnly, "built-in")
}

func TestDeferredUpdateConfiguration(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "user.yaml")
	updateDir := filepath.Join(dir, "templates")
	writeConfigFile(t, userPath, fmt.Sprintf(`
disable-update-check: true
update: true
update-templates: true
update-template-dir: %q
`, updateDir))

	var disableUpdateCheck, updateBinary, updateTemplates, noop bool
	var selected Selection
	var selectedUpdateDir string
	flagSet := goflags.NewFlagSet()
	flagSet.BoolVar(&disableUpdateCheck, "disable-update-check", false, "")
	flagSet.BoolVar(&updateBinary, "update", false, "")
	flagSet.BoolVar(&updateTemplates, "update-templates", false, "")
	flagSet.StringVar(&selectedUpdateDir, "update-template-dir", "", "")
	flagSet.StringVar(&selected.Config, "config", "", "")
	flagSet.StringVar(&selected.Profile, "profile", "", "")
	flagSet.BoolVar(&noop, "noop", false, "")

	automaticErr, err := loadTestFlags(flagSet, []string{filepath.Join(dir, "missing-system.yaml"), userPath}, &selected, existingProfilePath, "-noop=false")
	if err != nil {
		t.Fatalf("load configuration failed: %v", err)
	}
	if automaticErr != nil {
		t.Fatalf("automatic configuration failed: %v", automaticErr)
	}
	if !disableUpdateCheck || !updateBinary || !updateTemplates {
		t.Fatalf("update values were not loaded: disable=%t update=%t templates=%t", disableUpdateCheck, updateBinary, updateTemplates)
	}
	assertEqual(t, "update template directory", selectedUpdateDir, updateDir)

	testConfig := &catalogconfig.Config{}
	if !testConfig.CanCheckForUpdates() {
		t.Fatal("configuration loading applied disable-update-check too early")
	}
	if disableUpdateCheck {
		testConfig.DisableUpdateCheck()
	}
	if testConfig.CanCheckForUpdates() {
		t.Fatal("deferred disable-update-check was not applied")
	}
}

func TestConfigFilesDoNotExecuteCallbacks(t *testing.T) {
	dir := t.TempDir()
	systemPath := filepath.Join(dir, "system.yaml")
	userPath := filepath.Join(dir, "user.yaml")
	explicitPath := filepath.Join(dir, "explicit.yaml")
	profilePath := filepath.Join(dir, "profile.yaml")
	callbackYAML := "reset: true\nversion: true\ntemplates-version: true\n"
	writeConfigFile(t, systemPath, callbackYAML)
	writeConfigFile(t, userPath, fmt.Sprintf("%sconfig: %q\n", callbackYAML, explicitPath))
	writeConfigFile(t, explicitPath, fmt.Sprintf("%sprofile: %q\n", callbackYAML, profilePath))
	writeConfigFile(t, profilePath, callbackYAML)

	callbackCount := 0
	var selected Selection
	var noop bool
	flagSet := goflags.NewFlagSet()
	flagSet.CallbackVar(func() { callbackCount++ }, "reset", "")
	flagSet.CallbackVar(func() { callbackCount++ }, "version", "")
	flagSet.CallbackVar(func() { callbackCount++ }, "templates-version", "")
	flagSet.StringVar(&selected.Config, "config", "", "")
	flagSet.StringVar(&selected.Profile, "profile", "", "")
	flagSet.BoolVar(&noop, "noop", false, "")

	automaticErr, err := loadTestFlags(flagSet, []string{systemPath, userPath}, &selected, existingProfilePath, "-noop=false")
	if err != nil {
		t.Fatalf("load configuration failed: %v", err)
	}
	if automaticErr != nil {
		t.Fatalf("automatic configuration failed: %v", automaticErr)
	}
	if callbackCount != 0 {
		t.Fatalf("configuration executed %d callbacks", callbackCount)
	}

	flagSet = goflags.NewFlagSet()
	flagSet.CallbackVar(func() { callbackCount++ }, "reset", "")
	flagSet.StringVar(&selected.Config, "config", "", "")
	flagSet.StringVar(&selected.Profile, "profile", "", "")
	automaticErr, err = loadTestFlags(flagSet, []string{systemPath, userPath}, &selected, existingProfilePath, "-reset")
	if err != nil {
		t.Fatalf("load configuration with CLI callback failed: %v", err)
	}
	if automaticErr != nil {
		t.Fatalf("automatic configuration with CLI callback failed: %v", automaticErr)
	}
	if callbackCount != 1 {
		t.Fatalf("CLI callback count = %d, want 1", callbackCount)
	}
}

func TestSelectedFilesCannotRedirectTheirOwnStage(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "user.yaml")
	configPath := filepath.Join(dir, "config.yaml")
	otherConfigPath := filepath.Join(dir, "other-config.yaml")
	profilePath := filepath.Join(dir, "profile.yaml")
	otherProfilePath := filepath.Join(dir, "other-profile.yaml")

	writeConfigFile(t, userPath, fmt.Sprintf("config: %q\n", configPath))
	writeConfigFile(t, configPath, fmt.Sprintf("config: %q\nprofile: %q\n", otherConfigPath, profilePath))
	writeConfigFile(t, otherConfigPath, "other-config-loaded: true\n")
	writeConfigFile(t, profilePath, fmt.Sprintf("config: %q\nprofile: %q\n", otherConfigPath, otherProfilePath))
	writeConfigFile(t, otherProfilePath, "other-profile-loaded: true\n")

	var selected Selection
	var otherConfigLoaded, otherProfileLoaded bool
	flagSet := goflags.NewFlagSet()
	flagSet.StringVar(&selected.Config, "config", "", "")
	flagSet.StringVar(&selected.Profile, "profile", "", "")
	flagSet.BoolVar(&otherConfigLoaded, "other-config-loaded", false, "")
	flagSet.BoolVar(&otherProfileLoaded, "other-profile-loaded", false, "")

	automaticErr, err := loadTestFlags(flagSet, []string{userPath}, &selected, existingProfilePath, "--")
	if err != nil {
		t.Fatalf("load configuration failed: %v", err)
	}
	if automaticErr != nil {
		t.Fatalf("automatic configuration failed: %v", automaticErr)
	}
	assertEqual(t, "selected config", selected.Config, configPath)
	assertEqual(t, "selected profile", selected.Profile, profilePath)
	if otherConfigLoaded || otherProfileLoaded {
		t.Fatalf("loading followed a redirected stage: config=%t profile=%t", otherConfigLoaded, otherProfileLoaded)
	}
}

func loadTestFlags(
	flagSet *goflags.FlagSet,
	automaticFiles []string,
	selected *Selection,
	resolveProfile func(string) (string, error),
	args ...string,
) (error, error) {
	userConfigFile := automaticFiles[len(automaticFiles)-1]
	warnings, err := loadConfigFiles(userConfigFile, userConfigFile, automaticFiles, flagSet, selected, resolveProfile, args...)
	return errors.Join(warnings...), err
}

func existingProfilePath(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}
	return path, nil
}

func writeConfigFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimPrefix(content, "\n")), 0o600); err != nil {
		t.Fatalf("write config file %q: %v", path, err)
	}
}

func assertEqual[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}
