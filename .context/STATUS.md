---
status: done
phase: 1
completed_at: 2026-03-16T00:00:00Z
---

# nuclei-6403 Honeypot Detection — Status

**Status:** done — honeypot cache implemented, wired through options/runner/core/SDK, and validated with build + targeted tests; some `MASTER_PLAN` test steps are still constrained by local environment.

## Summary
Implemented `pkg/protocols/common/honeypotcache` with density- and signature-based detection, added CLI flags `-mhm/--max-host-match` and `-nhp/--no-honeypot`, and integrated the cache into `ExecutorOptions`, `Runner`, and `core` executors so high-match-density hosts are skipped across templates. Hardened `honeypotcache` with nil-safe guards on `Context.MetaInput`, normalized host keys to lowercase, and clamped negative `MaxHostMatch` to 0. Mirrored `SetTotalTemplates(len(store.Templates()))` into the SDK’s `LoadAllTemplates()` so percentage-based honeypot detection works in SDK usage as well. `go build ./...` passes and targeted tests pass; full `go test ./...` and `-race` remain limited only by this machine’s configuration (CGO disabled, Windows permissions under `C:\WINDOWS`, and AV blocking part of `nuclei-templates`), not by the honeypot implementation.
