# Fuzzing

Nuclei uses `go-fuzz` for targeted harnesses behind the `gofuzz` build tag.

## Targets

The Makefile exposes these go-fuzz targets:

```bash
make build-fuzz GOFUZZ_PACKAGE=./pkg/operators/matchers
make fuzz GOFUZZ_PACKAGE=./pkg/operators/matchers
```

Required variable:

- `GOFUZZ_PACKAGE`: any package path that `go list` can resolve from the repo root. The normal form in this repo is a relative package path such as `./pkg/operators/matchers`.

`build-fuzz`, `fuzz`, and `fuzz-ci` derive everything else from that package path:

- workdir: `<package>/.gofuzz/`
- seed corpus: `<package>/testdata/gofuzz-corpus/`
- instrumented archive: `<package>/.gofuzz/<pkgname>-fuzz.zip`

`discover-fuzz-packages` emits the GitHub Actions matrix JSON to stdout, and writes `matrix=...` to `GITHUB_OUTPUT` when that file is present.

`fuzz-ci` wraps `make fuzz` in the CI timeout.

`build-fuzz` and `fuzz` fail immediately if `GOFUZZ_PACKAGE` is missing, the package cannot be resolved, or the seed corpus directory is missing or empty.

## Examples

Operators (matchers & extractors) harness:

```bash
make fuzz GOFUZZ_PACKAGE=./pkg/operators/matchers
make fuzz GOFUZZ_PACKAGE=./pkg/operators/extractors
```

**Harness Coverage**:

Matchers exercise `Matcher.CompileMatchers()` through a compact line-based grammar. Supported keys are:

- `type`
- `condition`
- `part`
- `encoding`
- `negative`
- `case-insensitive`
- `match-all`
- `name`
- `value`
- `status`
- `size`

Extractors exercise `Extractor.CompileExtractors()` and the matching extraction path with fixed local corpora. Supported keys are:

- `type`
- `part`
- `name`
- `internal`
- `case-insensitive`
- `group`
- `attribute`
- `value`
- `regex`
- `kval`
- `json`
- `xpath`
- `dsl`

## Artifacts

Each run writes under `<package>/.gofuzz/`:

- `corpus/`: evolving seed corpus used by `go-fuzz`.
- `crashers/`: saved crashing inputs.
- `*-fuzz.zip`: the instrumented build output created by `go-fuzz-build`.

Promote real crashers into ordinary regression tests in the owning package once the underlying issue is fixed.

## GitHub Actions

The repository also has a dedicated GitHub Actions fuzz workflow in `.github/workflows/fuzz.yaml`.

- Triggers: `workflow_dispatch` and a weekly `schedule`.
- Scheduled runs: limited to `projectdiscovery/nuclei`; manual dispatch still works in forks.
- Matrix source: any package that has committed seeds under `testdata/gofuzz-corpus/` and a sibling `fuzz.go` harness.
- Current package matrix: `./pkg/operators/matchers` and `./pkg/operators/extractors`.
- Runtime model: discovery runs `make discover-fuzz-packages`, and each package runs `CI=true make fuzz-ci GOFUZZ_PACKAGE=... FUZZ_DURATION=15m`.
- Artifacts: each matrix job uploads the full `<package>/.gofuzz/` as the artifacts.
- Failure policy: crashers are summarized and uploaded, but they do not fail the workflow; build/setup errors still fail the job.