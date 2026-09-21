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


## Per-target profiles

A list input line starting with `{` is a target line: a JSON object binding one target to its own template selection, so a single scan runs a different profile on each target. The keys mirror template profiles and CLI flags:

```jsonl
{"target": "https://a.example", "tags": ["thinkphp"]}
{"target": "https://b.example", "profile": "wordpress", "severity": ["critical", "high"]}
{"target": "https://c.example", "tech": ["Apache Tomcat", "Java"]}
{"target": "10.0.0.0/24", "type": "http", "exclude-tags": "dos"}
https://d.example
```

| Key | Selects |
| --- | --- |
| `target` | the target (URL, host, IP, CIDR or ASN), required |
| `profile` | a template profile by ID or path; the line's other keys override it |
| `templates` | template paths, relative to the templates directory |
| `tags`, `exclude-tags`, `include-tags`, `author`, `template-id`, `exclude-id`, `severity`, `exclude-severity`, `type`, `exclude-type` | same as the CLI flags |
| `tech` | technologies the target runs: templates bound to another product (`metadata.product`) are skipped, every other template runs |

- Global flags apply first; a target line only narrows them. Plain targets run every template.
- A target listed more than once runs the union of its selections, and is scanned once.
- When every target has a selection, only the templates some target selects are loaded.
- Unknown keys fail the run rather than widening the scan. Profile keys that configure the whole scan, such as `code` or `var`, are ignored per target.
- Not supported with `-automatic-scan`. Global matchers still apply to every target.

## Formats

Fuzzing and DAST take the request shape (method, body, params) from the input, not from CLI flags, so a bare URL is always fuzzed as a `GET`. To fuzz anything else, feed a request-shaped input with `-im`:

| `-im` | Input |
| --- | --- |
| `list` | urls, domains, ips, cidrs (default) |
| `http` | raw HTTP requests |
| `burp` | Burp Suite xml export |
| `jsonl` | proxify jsonl output |
| `yaml` | proxify yaml multidoc output |
| `openapi` | OpenAPI 3 spec |
| `swagger` | Swagger 2 spec |

### Raw HTTP requests (`-im http`)

The shortest path from a single endpoint to a DAST scan, for targets with no spec or captured traffic. Save the request as it appears on the wire, which is what "copy as raw request" in Burp and browser devtools produce:

```
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"user":"admin","pass":"secret"}
```

```console
nuclei -l login.http -im http -dast -t fuzzing-templates/
```

Notes:

- Separate multiple requests with a line starting with `###`, the `.http` file convention.
- The scheme is not part of the request, so it is inferred from the authority. Use an absolute request target (`POST https://example.com/api/login HTTP/1.1`) to state it explicitly.
- The target comes from the `Host` header or from an absolute request target; a request carrying neither is skipped.

