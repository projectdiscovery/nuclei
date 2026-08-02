# Markdown and security change report

This file is a standalone, downloadable summary of the Markdown report filename
hardening and Go vulnerability remediation work.

## Executive summary

The change set:

- prevents Markdown report paths from being influenced by directory traversal
  sequences;
- prevents long template IDs and hosts from removing the per-finding UUID;
- includes the selected matcher or extractor name in result filenames;
- truncates filenames without producing invalid UTF-8;
- updates the Go toolchain and vulnerable dependencies; and
- reduces reachable `govulncheck` findings from 23 to one upstream advisory
  with no fixed dependency version.

## Markdown filename hardening

Markdown finding files use this structure:

```text
<template-id>-<host>-<uuid>-<matcher-or-extractor>.md
```

The matcher name is selected when both a matcher and extractor name are
available. Extractor-only findings use the extractor name.

Before a file is written, unsafe filesystem characters, path separators, and
parent-directory references are replaced. The resulting filename is limited to
255 bytes and truncated only at a valid UTF-8 boundary. Prefix truncation does
not remove the UUID or `.md` extension, so findings cannot collide merely
because their long template and host prefixes are identical.

## Dependency remediation

| Component | Previous version | Updated version |
| --- | --- | --- |
| Go toolchain | 1.26.0 | 1.26.5 |
| `golang.org/x/text` | v0.38.0 | v0.39.0 |
| `github.com/yuin/goldmark` | v1.7.13 | v1.7.17 |
| Direct `github.com/google/go-github` use | v30.1.0 | v81.0.0 |

The direct GitHub client migration covers the custom-template downloader and
GitHub reporting tracker. Module metadata was refreshed after the upgrades.

## Vulnerability scan result

The initial source scan reported 23 reachable vulnerabilities. After the
updates, the scan reports only GO-2026-5932.

GO-2026-5932 remains reachable through the latest available
`github.com/projectdiscovery/utils/update` dependency, which transitively uses
`github.com/google/go-github/v30` and `golang.org/x/crypto/openpgp`. The advisory
does not identify a fixed `golang.org/x/crypto` release. Eliminating this final
result requires the upstream update package to migrate away from the older
GitHub client or a replacement of that update subsystem.

Run the vulnerability scan with:

```console
go run golang.org/x/vuln/cmd/govulncheck@latest \
  -db=https://storage.googleapis.com/go-vulndb ./...
```

An exit status indicating GO-2026-5932 is expected until the upstream
dependency is migrated.

## Validation commands

```console
go mod verify
go test ./pkg/reporting/exporters/markdown
go test ./pkg/external/customtemplates -run '^$'
go test ./pkg/reporting/trackers/github
go vet ./pkg/external/customtemplates \
  ./pkg/reporting/trackers/github \
  ./pkg/reporting/exporters/markdown
```

The `-run '^$'` custom-template command checks compilation without running the
network-dependent GitHub download tests.

## Detailed documentation

- [Markdown report filenames](markdown-report-filenames.md)
- [Go vulnerability remediation](security-remediation.md)
