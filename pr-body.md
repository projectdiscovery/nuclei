## Description

Fixes issue #7165 - Path component uses regular map instead of OrderedMap, causing path segment ordering issues during fuzzing.

## Changes

- Replace `map[string]interface{}` with `mapsutil.OrderedMap` in Parse() function
- Use `KV.Get()` instead of `Map.GetOrDefault()` in Rebuild() function
- Ensures consistent ordering of path segments when fuzzing

## Bug Description

When using path-based fuzzing (e.g., `fuzz-path-sqli.yaml`), numeric path segments like `/user/55/profile` were being skipped as "not applicable for fuzzing". This was caused by using a regular Go map which doesn't maintain insertion order, leading to inconsistent key ordering for path segments.

## Testing

This fix ensures that path segments maintain their original order during fuzzing operations, allowing all segments (including numeric ones like `55`) to be properly fuzzed.
