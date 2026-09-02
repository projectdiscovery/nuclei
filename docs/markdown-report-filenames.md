# Markdown report filenames

The Markdown exporter writes one result file per finding. Result filenames are
constructed from the template ID, target host, a random UUID, and—when
available—the operator name:

```text
<template-id>-<host>-<uuid>-<matcher-or-extractor>.md
```

The matcher name takes precedence when a result contains both a matcher name
and an extractor name. For extractor-only results, the extractor name is used.

## Safety properties

Filename components can contain values derived from templates or scan targets,
so the exporter applies the following rules before writing a report:

1. Path separators, parent-directory references, spaces, and characters that
   are unsafe on common filesystems are replaced with underscores.
2. Filenames are limited to 255 bytes.
3. Truncation stops at a valid UTF-8 boundary.
4. The UUID and `.md` extension are always retained when the template ID or
   host must be truncated.
5. The operator name is sanitized and truncated separately from the prefix.

Preserving the UUID prevents two findings with long, identical prefixes from
being truncated to the same filename and overwriting each other. Sanitizing
path separators and `..` prevents target-controlled values from escaping the
configured report directory.

## Verification

The Markdown exporter tests cover:

- matcher-only and extractor-only filenames;
- matcher precedence when both operator names are present;
- UUID and operator suffix preservation for long names;
- UTF-8-safe truncation; and
- containment of filenames and sort-mode subdirectories within the report
  directory.

Run the tests with:

```console
go test ./pkg/reporting/exporters/markdown
```
