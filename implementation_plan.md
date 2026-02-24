# Implementation Plan - Nuclei Phase 2

## Goal
Update external call sites to handle the new error return from 'LoadTemplates' and 'LoadTemplatesWithTags'.

## Proposed Changes
### runner package
- [MODIFY] [lazy.go](file:///home/pitrat/.openclaw/workspace/projects/nuclei-panic-fix/internal/runner/lazy.go)
  - Handle error from 'LoadTemplates' instead of ignoring it.

### automaticscan package
- [MODIFY] [automaticscan.go](file:///home/pitrat/.openclaw/workspace/projects/nuclei-panic-fix/pkg/protocols/common/automaticscan/automaticscan.go)
  - Propagate error from template loading back to the engine.

## Verification Plan
### Automated Tests
- Run 'go test ./pkg/catalog/loader/...' to verify core logic.
- Run 'go test ./internal/runner/...' to verify integration.
