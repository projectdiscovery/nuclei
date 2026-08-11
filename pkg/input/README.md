## input

input package contains and provides loading, parsing , validating and normalizing of input data


## [transform](./transform.go)

Transform package transforms or normalizes the input data before it is sent to protocol executer this step mainly involves changes like adding default ports (if missing) , validating if input is file or directory or url and adjusting the input accordingly etc.


## Provider

Provider package contains the interface that every input format should implement for providing that input format to nuclei.

Currently Nuclei Supports three input providers:

1. SimpleInputProvider = A No-Op provider that takes a list of urls and implements the provider interface.

2. HttpInputProvider = A provider that supports loading and parsing input formats that contain complete Http Data like Entire Request, Response etc. Supported formats include Burp,openapi,swagger,postman,proxify etc.

3. ListInputProvider = Legacy/Default Provider that handles all list type inputs like urls,domains,ips,cidrs,files etc.


```go
func NewInputProvider(opts InputOptions) (InputProvider, error)
```

This function returns a InputProvider based by appropriately selecting input provider based on the input format (i.e. either list or http) and returns the provider that can handle that input format.

## Per-target JSONL filters

JSONL input can attach template-selection overrides to individual URL targets:

```jsonl
{"url":"https://target-a.example","tags":["apache","shiro"],"severity":["critical","high"]}
{"url":"https://target-b.example","exclude-tags":["tomcat"],"templates":["http/cves/2026/"]}
{"url":"https://target-c.example"}
```

Run the scan with:

```console
nuclei -l targets.jsonl -input-mode jsonl
```

The optional `tags`, `exclude-tags`, `severity`, and `templates` fields mirror
their global CLI counterparts. An omitted field inherits the global option;
an explicitly empty array clears that option for the target. Global
`-include-templates` selections remain forced includes, and `-exclude-hosts`
is applied before target execution. Two global exclusions always stay in
effect: built-in ignore-file tags are not re-enabled by a target-level
`exclude-tags`, and `-exclude-severity` cannot be bypassed by a target-level
`severity`, even when those target fields are explicitly empty.

Per-target `templates` overrides currently support local selectors only and
cannot be combined with global remote templates. Each selector must stay within
the templates directory: absolute paths and `../` parent-directory traversal are
rejected, so a targets file cannot point the loader at arbitrary files on disk.
Use the global `-t` flag for templates outside the templates tree. Any per-target override is
incompatible with automatic scan, workflows, and global matchers.
JSONL files in the existing Proxify request/response format remain supported,
but target and Proxify records cannot be mixed in one file.
