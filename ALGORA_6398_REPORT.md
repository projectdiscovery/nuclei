# ALGORA Report: nuclei issue #6398 (numeric path fuzz parts skipped)

## Branch
- `fix/algora-6398-numeric-path-fuzz`

## Root Cause
Path component parsing stored path segments in a plain map and fed them through generic value parsing/flattening (`Value.SetParsed`), which is not ideal for ordered path-part mutation.

Two failure modes followed from this:
1. Path segments were not kept in an ordered key/value container designed for request fuzz components.
2. Rebuild path replacement relied on a strict string type assertion from the parsed map (`.(string)`), so any non-string representation caused fallback to the original segment.

In practice this could cause numeric path segments to be skipped or rebuilt unchanged during fuzz mutation, matching issue #6398 behavior.

## Changes Implemented

### 1) Path parse/rebuild logic hardened
File: `pkg/fuzz/component/path.go`

- Parse now stores path segments in an ordered map (`mapsutil.NewOrderedMap[string, any]`) and sets parsed value via `dataformat.KVOrderedMap(...)`.
- Rebuild now reads replacement values using `q.value.parsed.Get(key)` and converts via `fmt.Sprint(...)` instead of strict `string` assertion.
- This ensures numeric path segments are preserved/mutated consistently and rebuilt correctly.

### 2) Regression unit test added
File: `pkg/fuzz/component/path_test.go`

- Added `TestPathComponent_EncodedPayloadOnNumericSegment`.
- Test covers encoded SQL payload mutation on numeric segment (`/user/55/profile` + `%20OR%20True`) and asserts resulting path mutates as expected (`/user/55 OR True/profile`).

### 3) Integration template aligned to numeric-path intent
File: `integration_tests/fuzz/fuzz-path-sqli.yaml`

- Added fuzz value filter:
  - `values: ["^[0-9]+$"]`
- This makes the integration path SQLi case explicitly target numeric path segments, matching issue intent.

## Validation

## Commands run
```bash
git checkout -b fix/algora-6398-numeric-path-fuzz
gofmt -w pkg/fuzz/component/path.go pkg/fuzz/component/path_test.go
```

## Test attempts and outputs
Targeted and package tests were attempted, but execution was blocked by sandbox/toolchain constraints:

1. Default `go test` path:
```text
go: downloading go1.24.4 (linux/amd64)
go: download go1.24.4: ... Get "https://proxy.golang.org/...":
... socket: operation not permitted
```

2. Forced local toolchain (`GOTOOLCHAIN=local`):
```text
go: go.mod requires go >= 1.24.2 (running go 1.22.2; GOTOOLCHAIN=local)
```

So, tests could not be executed in this environment. Code was formatted and reviewed for compile-time consistency.

## Risk Assessment
- Low risk: path component logic only, with explicit regression test coverage added.
- Behavioral impact:
  - Path segment ordering and mutation stability improved.
  - Rebuild now tolerates non-string internals safely via `fmt.Sprint`.
- Potential edge impact:
  - If a caller intentionally stored non-string-typed path segment values, they are now serialized rather than silently dropped/reverted, which is preferable for fuzz mutation behavior.

## Files Changed
- `pkg/fuzz/component/path.go`
- `pkg/fuzz/component/path_test.go`
- `integration_tests/fuzz/fuzz-path-sqli.yaml`
