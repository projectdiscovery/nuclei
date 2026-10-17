// Package app implements the local desktop interface: a small HTTP server
// with a browser UI to run scans, watch results arrive live and operate the
// deployed webshells. It is started with -app and keeps the single-binary,
// dependency-free deployment of the CLI.
package app

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/postexploit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/rs/xid"
)

//go:embed ui
var uiFS embed.FS

// App holds the desktop session: the current scan job and the shells
// accumulated across scans.
type App struct {
	base *types.Options
	port int

	mu      sync.Mutex
	scan    scanState
	started time.Time
	shells  []trackedShell
	nextID  int
	labDir  string
}

type trackedShell struct {
	ID  int                       `json:"id"`
	Sh  postexploit.DeployedShell `json:"sh"`
	Mgr *postexploit.Manager      `json:"-"`
}

type scanState struct {
	Running bool        `json:"running"`
	Elapsed string      `json:"elapsed"`
	Error   string      `json:"error"`
	Results []resultRow `json:"results"`
}

type resultRow struct {
	Template  string   `json:"template"`
	Severity  string   `json:"severity"`
	URL       string   `json:"url"`
	Matched   string   `json:"matched"`
	Extracted []string `json:"extracted,omitempty"`
}

type scanRequest struct {
	Target   string `json:"target"`
	Preset   string `json:"preset"` // lab | full | custom
	Path     string `json:"path"`
	Tags     string `json:"tags"`
	Exploit  bool   `json:"exploit"`
	UDF      bool   `json:"udf"`
	Clean    bool   `json:"clean"`
	PortScan bool   `json:"pscan"`
	Ports    string `json:"ports"`
}

// New prepares the desktop app and materialises the embedded lab templates
// into a temporary directory so they can be used as a template preset.
func New(base *types.Options) (*App, error) {
	dir, err := writeLabTemplates()
	if err != nil {
		return nil, err
	}
	port := base.AppPort
	if port <= 0 {
		port = 8977
	}
	return &App{base: base, port: port, labDir: dir}, nil
}

// Serve starts the local web interface and blocks until interrupted.
func (a *App) Serve() error {
	// the UI is the result channel; keep found results off the terminal
	// (understood by output.NewStandardWriter)
	_ = os.Setenv("DISABLE_STDOUT", "1")

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/api/state", a.handleState)
	mux.HandleFunc("/api/scan", a.handleScan)
	mux.HandleFunc("/api/exec", a.handleExec)
	mux.HandleFunc("/api/ls", a.handleLS)
	mux.HandleFunc("/api/cleanup", a.handleCleanup)

	addr := fmt.Sprintf("127.0.0.1:%d", a.port)
	srv := &http.Server{Addr: addr, Handler: mux}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		return err
	case <-time.After(300 * time.Millisecond):
	}

	url := "http://" + addr
	fmt.Fprintf(os.Stderr, "桌面界面已启动: %s (Ctrl+C 退出)\n", url)
	openBrowser(url)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	fmt.Fprintln(os.Stderr, "正在关闭…")
	_ = srv.Close()
	return nil
}

// ---- handlers -------------------------------------------------------------

func (a *App) handleIndex(w http.ResponseWriter, _ *http.Request) {
	page, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(page)
}

func (a *App) handleState(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshElapsed()
	writeJSON(w, map[string]any{"scan": a.scan, "shells": a.shells})
}

func (a *App) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		http.Error(w, "缺少目标地址", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	if a.scan.Running {
		a.mu.Unlock()
		http.Error(w, "扫描正在进行中", http.StatusConflict)
		return
	}
	a.scan = scanState{Running: true}
	a.started = time.Now()
	a.mu.Unlock()

	go a.runScan(req)
	writeJSON(w, map[string]any{"ok": true})
}

type shellRequest struct {
	ID   int    `json:"id"`
	Cmd  string `json:"cmd"`
	Path string `json:"path"`
}

func (a *App) handleExec(w http.ResponseWriter, r *http.Request) {
	var req shellRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sh, ok := a.shellByID(req.ID)
	if !ok {
		http.Error(w, "木马不存在", http.StatusNotFound)
		return
	}
	out := sh.Mgr.ShellExec(sh.Sh, req.Cmd)
	writeJSON(w, map[string]any{"output": out})
}

func (a *App) handleLS(w http.ResponseWriter, r *http.Request) {
	var req shellRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sh, ok := a.shellByID(req.ID)
	if !ok {
		http.Error(w, "木马不存在", http.StatusNotFound)
		return
	}
	out := sh.Mgr.ShellLS(sh.Sh, req.Path)
	writeJSON(w, map[string]any{"output": out})
}

func (a *App) handleCleanup(w http.ResponseWriter, r *http.Request) {
	var req shellRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	idx := -1
	for i := range a.shells {
		if a.shells[i].ID == req.ID {
			idx = i
			break
		}
	}
	if idx < 0 {
		a.mu.Unlock()
		http.Error(w, "木马不存在", http.StatusNotFound)
		return
	}
	out := a.shells[idx].Mgr.ShellCleanup(a.shells[idx].Sh)
	a.shells = append(a.shells[:idx], a.shells[idx+1:]...)
	a.mu.Unlock()
	writeJSON(w, map[string]any{"output": out})
}

// ---- scan job -------------------------------------------------------------

func (a *App) runScan(req scanRequest) {
	finish := func(err error) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.scan.Elapsed = time.Since(a.started).Round(time.Millisecond).String()
		a.scan.Running = false
		if err != nil {
			a.scan.Error = err.Error()
		}
	}

	opts := *a.base //nolint:govet // copylocks: intentional independent copy
	opts.App = false
	opts.Console = false
	// fresh execution id per scan: protocolstate dialers are registered
	// globally per id and torn down on Close, so consecutive scans in one
	// process must not share it (mirrors the CLI, one id per process)
	opts.ExecutionId = xid.New().String()
	if ierr := protocolinit.Init(&opts); ierr != nil {
		finish(ierr)
		return
	}
	opts.Silent = true
	opts.Targets = goflags.StringSlice{strings.TrimSpace(req.Target)}
	switch req.Preset {
	case "full":
		opts.Templates = nil // default installed nuclei-templates
	case "custom":
		opts.Templates = goflags.StringSlice{strings.TrimSpace(req.Path)}
	default:
		opts.Templates = goflags.StringSlice{a.labDir}
	}
	if tags := splitCSV(req.Tags); len(tags) > 0 {
		opts.Tags = tags
	} else {
		opts.Tags = nil
	}
	opts.Exploit = req.Exploit
	opts.ExploitUDF = req.UDF
	opts.WebShellClean = req.Clean
	opts.PortScan = req.PortScan
	if ports := splitCSV(req.Ports); len(ports) > 0 {
		opts.PortScanPorts = ports
	}

	r, err := runner.NewWithResultCallback(&opts, a.observe)
	if err != nil {
		protocolinit.Close(opts.ExecutionId)
		finish(err)
		return
	}
	scanErr := r.RunEnumeration()
	if m := r.PostExploit(); m != nil {
		for _, sh := range m.Shells() {
			a.mu.Lock()
			a.shells = append(a.shells, trackedShell{ID: a.nextID, Sh: sh, Mgr: m})
			a.nextID++
			a.mu.Unlock()
		}
	}
	r.Close()
	finish(scanErr)
}

// observe appends one result to the live UI table.
func (a *App) observe(ev *output.ResultEvent) {
	if ev == nil || !ev.MatcherStatus {
		return
	}
	matched := ev.Matched
	if matched == "" {
		matched = ev.URL
	}
	row := resultRow{
		Template:  ev.TemplateID,
		Severity:  ev.Info.SeverityHolder.Severity.String(),
		URL:       ev.URL,
		Matched:   matched,
		Extracted: ev.ExtractedResults,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshElapsed()
	a.scan.Results = append(a.scan.Results, row)
}

// ---- helpers --------------------------------------------------------------

func (a *App) shellByID(id int) (trackedShell, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, sh := range a.shells {
		if sh.ID == id {
			return sh, true
		}
	}
	return trackedShell{}, false
}

// refreshElapsed updates the elapsed counter; caller holds a.mu.
func (a *App) refreshElapsed() {
	if a.scan.Running {
		a.scan.Elapsed = time.Since(a.started).Round(time.Millisecond).String()
	}
}

func splitCSV(s string) goflags.StringSlice {
	var out goflags.StringSlice
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// writeLabTemplates materialises the embedded lab templates to disk so the
// engine can load them like any template directory.
func writeLabTemplates() (string, error) {
	dir, err := os.MkdirTemp("", "nuclei-lab-")
	if err != nil {
		return "", err
	}
	entries, err := fs.ReadDir(postexploit.LabTemplates, "tests/lab")
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		data, err := postexploit.LabTemplates.ReadFile("tests/lab/" + e.Name())
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), data, 0o600); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
