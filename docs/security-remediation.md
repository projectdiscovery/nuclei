# Go vulnerability remediation

## Scope

A `govulncheck` source scan was performed for all Go packages. The initial scan
reported 23 reachable vulnerabilities in the Go standard library and direct or
transitive dependencies.

The remediation updates the following components:

| Component | Previous | Remediated | Purpose |
| --- | --- | --- | --- |
| Go toolchain | 1.26.0 | 1.26.5 | Includes standard-library security fixes |
| `golang.org/x/text` | v0.38.0 | v0.39.0 | Fixes GO-2026-5970 |
| `github.com/yuin/goldmark` | v1.7.13 | v1.7.17 | Fixes GO-2026-5320 |
| `github.com/google/go-github` (direct use) | v30.1.0 | v81.0.0 | Removes Nuclei's direct dependency path through the deprecated OpenPGP API |

The GitHub client migration applies to the custom-template downloader and the
GitHub reporting tracker.

## Verification command

The default Go vulnerability database endpoint may be unavailable in restricted
environments. The equivalent Google Cloud Storage database mirror can be used:

```console
go run golang.org/x/vuln/cmd/govulncheck@latest \
  -db=https://storage.googleapis.com/go-vulndb ./...
```

After remediation, the scan reports one reachable advisory instead of 23.

## Remaining upstream advisory

GO-2026-5932 remains reachable through
`github.com/projectdiscovery/utils/update`, which transitively depends on
`github.com/google/go-github/v30` and its use of
`golang.org/x/crypto/openpgp`.

The advisory describes the OpenPGP package as unmaintained and unsafe by
design, and the Go vulnerability database does not provide a fixed
`golang.org/x/crypto` version. Nuclei already uses `go-github/v81` for its own
GitHub API integrations, but the older module remains in the dependency graph
until `projectdiscovery/utils` migrates its update package.

The remaining advisory therefore cannot be resolved by upgrading
`golang.org/x/crypto`. It requires an upstream dependency migration or a local
replacement of the update subsystem.

## Validation

Use the following checks when changing these dependencies:

```console
go mod verify
go vet ./pkg/external/customtemplates \
  ./pkg/reporting/trackers/github \
  ./pkg/reporting/exporters/markdown
go test ./pkg/external/customtemplates -run '^$'
go test ./pkg/reporting/trackers/github \
  ./pkg/reporting/exporters/markdown
```

The custom-template package has tests that access external GitHub resources.
Using `-run '^$'` performs a compilation check without requiring network access.
