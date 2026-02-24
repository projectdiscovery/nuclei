# Nuclei Panic Fix ($100 Bounty)

## Vision
Replace `panic()` calls in `pkg/catalog/loader/loader.go` with proper error handling and propagation. This improves API stability and follows project conventions.

## Goals
- Remove panics from `protocolstate.GetDialersWithId()` checks.
- Propagate errors up the call stack.
- Ensure all callers handle the new error return.
- Pass all existing tests and add a regression test.

## Tech Stack
- Go (Golang)
- Nuclei Framework
- ProjectDiscovery Common Libs
