package code

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The native sandbox is the fallback for code templates when Docker is not
// reachable: bubblewrap on Linux, Seatbelt (sandbox-exec) on macOS. It differs
// from the gozero native confiners on purpose: those keep the whole host
// filesystem readable, which would expose credentials under the home
// directories. Here the payload gets one fresh writable workspace, no network,
// a scrubbed environment, and no access to home directories or runtime
// sockets (such as the Docker socket).

// errNativeSandboxUnavailable reports that no native sandbox works on this host.
var errNativeSandboxUnavailable = errors.New("no native sandbox available")

// nativePassEnv is the short list of host variables passed to the payload.
// Everything else in the host environment is dropped.
var nativePassEnv = []string{"LANG", "LC_ALL", "TERM", "TZ"}

const nativeDefaultPATH = "/usr/local/bin:/usr/bin:/bin"

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// nativeEnv builds the payload environment: PATH from the host, HOME and
// TMPDIR on the workspace, a few locale variables, then the template
// variables. Keys that are not identifiers are dropped.
func nativeEnv(workspace string, vars map[string]string) map[string]string {
	env := make(map[string]string, len(vars)+len(nativePassEnv)+3)
	path := os.Getenv("PATH")
	if path == "" {
		path = nativeDefaultPATH
	}
	env["PATH"] = path
	for _, key := range nativePassEnv {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			env[key] = value
		}
	}
	for key, value := range vars {
		if envKeyPattern.MatchString(key) {
			env[key] = value
		}
	}
	env["HOME"] = workspace
	env["TMPDIR"] = workspace
	return env
}

func envSlice(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

// seatbeltProfile builds the macOS sandbox-exec profile. Writes are denied
// everywhere except the workspace and a few /dev nodes, all network is denied
// (this also covers unix sockets such as the Docker socket), and the hidden
// directories (home directories) are denied for reads too. Seatbelt applies the
// last matching rule, so the workspace re-allow comes after the denies.
// All paths must be canonical: Seatbelt matches real paths.
func seatbeltProfile(workspace string, hidden []string) string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")
	b.WriteString("(deny network*)\n")
	b.WriteString("(deny file-write*)\n")
	b.WriteString("(allow file-write*\n")
	b.WriteString("  (subpath " + sbplString(workspace) + ")\n")
	b.WriteString("  (literal \"/dev/null\")\n")
	b.WriteString("  (literal \"/dev/zero\")\n")
	b.WriteString("  (literal \"/dev/stdout\")\n")
	b.WriteString("  (literal \"/dev/stderr\")\n")
	b.WriteString("  (regex #\"^/dev/fd/\")\n")
	b.WriteString("  (regex #\"^/dev/tty\")\n")
	// The /usr/bin interpreter shims (xcrun) write a lookup cache into the
	// per-user temp dir; without it every run prints an error on stderr.
	b.WriteString("  (regex #\"^/private/var/folders/[^/]+/[^/]+/T/xcrun_db\"))\n")
	if len(hidden) > 0 {
		b.WriteString("(deny file-read* file-write*\n")
		for _, dir := range hidden {
			b.WriteString("  (subpath " + sbplString(dir) + ")\n")
		}
		b.WriteString(")\n")
		b.WriteString("(allow file-read* file-write* (subpath " + sbplString(workspace) + "))\n")
	}
	return b.String()
}

// sbplString quotes a path as an SBPL string literal.
func sbplString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// bwrapArgs builds the bubblewrap command line. The host root is mounted
// read-only, every namespace is unshared (so there is no network), all
// capabilities are dropped, and the hidden directories (home directories and
// runtime socket directories) are replaced with empty read-only tmpfs mounts.
// The workspace is the only writable host path. Later mounts win, so the
// workspace bind comes after the tmpfs mounts.
func bwrapArgs(bin, workspace string, hidden []string, env map[string]string, argv []string) []string {
	out := []string{
		bin,
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--clearenv",
		"--cap-drop", "ALL",
		"--ro-bind", "/", "/",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
	}
	for _, dir := range hidden {
		out = append(out, "--tmpfs", dir)
	}
	out = append(out, "--bind", workspace, workspace)
	// Make the hidden tmpfs mounts read-only only after the workspace bind:
	// bwrap may need to create the workspace mount point inside one of them.
	// The workspace is its own mount, so it stays writable.
	for _, dir := range hidden {
		out = append(out, "--remount-ro", dir)
	}
	out = append(out, "--chdir", workspace)
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, "--setenv", key, env[key])
	}
	out = append(out, "--")
	return append(out, argv...)
}

// hiddenDirs returns the canonical, existing directories among candidates,
// plus the current user's home directory. Symlinks are resolved so a mount
// or a Seatbelt rule targets the real directory. Duplicates and directories
// inside another hidden directory are dropped.
func hiddenDirs(candidates ...string) []string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates, home)
	}
	seen := make(map[string]struct{}, len(candidates))
	out := make([]string, 0, len(candidates))
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(dir)
		if err != nil {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.IsDir() {
			continue
		}
		if _, ok := seen[resolved]; ok {
			continue
		}
		seen[resolved] = struct{}{}
		out = append(out, resolved)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	kept := out[:0]
	for _, dir := range out {
		nested := false
		for _, parent := range kept {
			if dir == parent || strings.HasPrefix(dir, parent+string(filepath.Separator)) {
				nested = true
				break
			}
		}
		if !nested {
			kept = append(kept, dir)
		}
	}
	return kept
}
