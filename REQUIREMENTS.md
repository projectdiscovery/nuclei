# Requirements - Nuclei Panic Fix

## Phase 1: Error Propagation
- [ ] R1.1: Modify `LoadTemplates` signature in `pkg/catalog/loader/loader.go` to return an error.
- [ ] R1.2: Replace `panic` at line 720 with `return fmt.Errorf`.
- [ ] R1.3: Update all internal calls within `loader.go` to handle the new error.

## Phase 2: Call Site Updates
- [ ] R2.1: Update `internal/runner/lazy.go` to handle the new error from `LoadTemplates`.
- [ ] R2.2: Update `pkg/protocols/common/automaticscan/` to handle the new error.

## Phase 3: Verification
- [ ] R3.1: Run `make test` for the modified packages.
- [ ] R3.2: Verify no regression in scanning flow.
