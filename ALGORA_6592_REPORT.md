# ALGORA 6592 Report

## Issue
- Repo: `projectdiscovery/nuclei`
- Issue: `#6592`
- Title: authenticated scanning starts executing templates before secret-file template finishes
- Branch used: `fix/algora-6592-auth-sequencing`

## Root Cause
Dynamic auth secret fetch had a concurrency gap in `pkg/authprovider/authx/dynamic.go`.

- `Dynamic.Fetch()` uses `fetching.CompareAndSwap(false, true)` to let a single goroutine run the dynamic-secret template callback.
- Before this patch, concurrent callers that saw `fetching=true` returned immediately with current `d.error` (often `nil`) instead of waiting.
- That allowed authenticated request generation to proceed while the secret-template fetch was still running, so strategies could be built from unresolved placeholders (for example `{{token}}`) rather than extracted values.

This matches the reported behavior: authenticated templates can start before secret-file auth setup finishes.

## Code Changes
1. Sequencing fix in dynamic fetch path
- File: `pkg/authprovider/authx/dynamic.go:211`
- Change: when a concurrent caller sees an in-progress fetch, it now waits for `d.fetched` before returning.
- Effect: all concurrent auth lookups for the same dynamic secret block until fetch callback finishes and extracted values are applied.

2. Regression test for execution ordering under concurrency
- File: `pkg/authprovider/authx/dynamic_test.go:130`
- Added test: `TestDynamicFetchConcurrentWaitsForCompletion`
- Test behavior:
  - starts two goroutines calling `GetStrategies()` simultaneously on the same `Dynamic` secret
  - callback intentionally sleeps (`120ms`) before setting extracted token
  - asserts both goroutines get resolved token (`resolved-token`) and both calls wait long enough (>= `100ms`), proving no early return with unresolved state

## Reproduce/Inspect Notes
I inspected the auth execution path and sequencing in:
- `internal/runner/runner.go` (auth provider initialization and scan startup)
- `internal/runner/lazy.go` (dynamic secret template callback)
- `pkg/protocols/http/build_request.go` and `pkg/protocols/http/request.go` (auth strategy application)
- `pkg/authprovider/authx/dynamic.go` (concurrent fetch behavior)

The new regression test encodes the previously racy interleaving and validates the corrected ordering.

## Validation
### Targeted tests (affected areas)
1. `GOCACHE=/tmp/go-build go test ./pkg/authprovider/...`
- Result: PASS
- Key output:
  - `ok github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx 0.385s`

2. `GOCACHE=/tmp/go-build go test ./internal/runner/...`
- Result: PASS
- Key output:
  - `ok github.com/projectdiscovery/nuclei/v3/internal/runner 0.145s`

### Full test run
3. `GOCACHE=/tmp/go-build go test ./...`
- Result: FAIL (environment-constrained, not specific to this patch)
- Representative blockers observed:
  - module cache permission denied under `/home/ubuntu/go/pkg/mod/cache/download/...`
  - DNS/network-restricted failures (`socket: operation not permitted`) in tests that require network/DNS/listeners
  - config/home-dir permission issues in some SDK/integration tests

Additional attempt with custom module cache:
4. `GOCACHE=/tmp/go-build GOMODCACHE=/tmp/go-mod go test ./...`
- Result: FAIL
- Blocker: toolchain/module download requires network access (`proxy.golang.org` lookup blocked in sandbox)

## Risks / Tradeoffs
- The wait loop introduces blocking for concurrent fetch callers of the same dynamic secret, which is intended for correctness and sequencing safety.
- Waiting uses a short sleep poll (`5ms`) until `fetched=true`; this is simple and low-risk but not condition-variable based.
- If a fetch callback hangs indefinitely, waiters will also block indefinitely (same fundamental failure mode as single-threaded fetch not completing).

## Blockers
- Full repo test suite cannot be fully validated in this sandbox due filesystem/network restrictions outside this patch’s scope.
- Required completion command execution failed in this environment:
  - Command: `openclaw system event --text 'Done: nuclei #6592 patch + report ready' --mode now`
  - Error: `SystemError [ERR_SYSTEM_ERROR]: uv_interface_addresses returned Unknown system error 1`
