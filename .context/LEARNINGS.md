# nuclei-6403 Honeypot Detection — Cursor Handoff

> **Instructions for Cursor:** Filled after execution for Claude’s next session.

---

## What Was Built
`pkg/protocols/common/honeypotcache/honeypotcache.go` — new honeypot cache package with per-host unique template tracking, percentage-based detection, static signature matching, and nil-safe guards on `Context` / `MetaInput`.  
`pkg/protocols/common/honeypotcache/honeypotcache_test.go` — unit tests covering thresholds, host normalization, uniqueness of template IDs, concurrency behavior, signature matching, and nil-safety.  
`pkg/types/types.go` — added `MaxHostMatch` and `NoHoneypot` to `Options` and wired them through `Copy()`.  
`cmd/nuclei/main.go` — registered `-mhm/--max-host-match` and `-nhp/--no-honeypot` flags in the optimization group.  
`pkg/protocols/protocols.go` — extended `ExecutorOptions` with `HoneypotCache` and propagated it via `Copy()` and `ApplyNewEngineOptions`.  
`internal/runner/runner.go` — instantiated `honeypotcache.Cache` when `!options.NoHoneypot`, clamped negative `MaxHostMatch` to 0, attached the cache to `ExecutorOptions`, and called `SetTotalTemplates(len(store.Templates()))` after `store.Load()`.  
`lib/sdk.go` — in SDK mode, called `SetTotalTemplates(len(e.store.Templates()))` in `LoadAllTemplates()` so percentage-based honeypot detection works outside the CLI runner as well.  
`pkg/core/executors.go` — added honeypot skip checks in `executeTemplateWithTargets` / `executeTemplatesOnTarget` and fed match density (plus optional signature-based boost) in `executeTemplateOnInput`, with nil-safe use of `ExecutorOptions`.

## Patterns Used
ExecutorOptions is always passed and copied by pointer; new fields must be added to both `Copy()` and `ApplyNewEngineOptions()` or they silently disappear.  
Runner initialization is the right place for global caches (host errors, honeypot), with template-count-dependent initialization done only after `store.Load()` completes.  
`scan.ScanContext` wraps a `contextargs.Context` as `Input`; any new per-request state should flow through that object rather than adding more fields to `ScanContext`.  
Host-level skip events for new conditions (honeypot) should mirror the existing `HostErrorsCache` pattern for logging and output behavior.

## Decisions Made
Called `SetTotalTemplates(len(store.Templates()))` in `runner.RunEnumeration` immediately after `store.Load()`, not earlier, to ensure the store is fully populated.  
Guarded all honeypot cache usage behind `e.executerOpts != nil` and `e.executerOpts.HoneypotCache != nil` so existing tests that construct an `Engine` without executor options continue to work.  
For signature-based boosting, defaulted to at least one extra `MarkMatch` even when `MaxHostMatch` is zero, so signatures still contribute to density when only percentage-based detection is active.  
Did not attempt to force `-race` or SQLite-backed tests to pass by changing build tags or CGO settings; treated those as environment constraints rather than modifying unrelated parts of the repo.

## Gotchas
`store.Templates()` returns a slice, not a collection type with `Len()`, so use `len(store.Templates())` when computing template counts.  
`scan.ScanContext` does not expose `ContextArgs`; the only exported handle to the meta input is `ScanContext.Input`, which is a `*contextargs.Context`.  
Core tests (e.g., `Test_executeTemplateOnInput_CallbackPath`) construct an `Engine` without setting `ExecutorOptions`; assuming `e.executerOpts` is non-nil in new code will panic tests even if the main binary works.  
Headless engine tests attempt to create directories under `C:\WINDOWS` and will fail on restricted Windows setups; similarly, some test utilities require `CGO_ENABLED=1` and a C toolchain (SQLite), which this environment does not provide.  
Antivirus can block nuclei-templates installation (e.g., CVE files flagged as malware), which prevents using certain template paths in integration smoke tests even though the binary itself works.

## Blockers
`go test ./pkg/protocols/common/honeypotcache/... -race -count=3` fails with `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` — the toolchain here is built with `CGO_ENABLED=0`.  
`go test ./...` surfaces pre-existing/environmental failures: headless engine tests try to `mkdir C:\WINDOWS\engine.test...` (access denied), and `pkg/testutils/fuzzplayground` panics because `go-sqlite3` requires cgo.  
Integration smoke test `go run ./cmd/nuclei -u http://localhost:8080 -t nuclei-templates/http/technologies/ -mhm 5 -v` cannot use the suggested templates path because antivirus blocks installation of at least one template file (`CVE-2017-12615.yaml`) as “virus or potentially unwanted software,” so the directory is incomplete and nuclei exits with “no templates provided for scan.”

## Open Questions
Should honeypot skip events be surfaced in standard output as explicit structured events (similar to host error skips) or remain only as logger warnings plus host-level skipping?  
Do maintainers want a separate CLI flag to control signature-based boosting (e.g., `--honeypot-signatures-only` or a way to disable signatures while keeping density)?  
Is the default 50% percentage threshold acceptable for all template sets, or should it be exposed as a separate flag in addition to `MaxHostMatch`?

## Test Results
`go test ./pkg/protocols/common/honeypotcache/...`:
```bash
ok  	github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/honeypotcache	0.154s
```

`go test ./pkg/protocols/common/honeypotcache/... -race -count=3` (environment-limited):
```bash
go: -race requires cgo; enable cgo by setting CGO_ENABLED=1
```

`go test ./pkg/core -run Test_executeTemplateOnInput_CallbackPath`:
```bash
ok  	github.com/projectdiscovery/nuclei/v3/pkg/core	0.258s
```

Full test run (`go test ./...`) — relevant failures due to environment, not honeypot code:
```bash
--- FAIL: TestBlockedHeadlessURLS (0.21s)
    page_actions_test.go:719:
        Error: Expected nil, but got: could not create dialer: mkdir C:\WINDOWS\engine.test3154972369: Access is denied.
        Messages: could not init protocol state
FAIL	github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless/engine

panic: Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work. This is a stub
FAIL	github.com/projectdiscovery/nuclei/v3/pkg/testutils/fuzzplayground
```

## Build Check
`go build ./...`:
```bash
go build ./...
# (no output; exit code 0)
```

