# Roadmap - Nuclei Panic Fix

## Phase 1: Core Loader Modification
- **Task 1.1**: Update `LoadTemplates` signature and replace panic in `loader.go`.
- **Task 1.2**: Update `LoadTemplatesWithTags` and other associated functions.

## Phase 2: External Callers
- **Task 2.1**: Update `runner` package callers.
- **Task 2.2**: Update `automaticscan` package callers.

## Phase 3: Final Testing
- **Task 3.1**: Integration testing with local nuclei build.
