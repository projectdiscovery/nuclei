# Bounty Task: projectdiscovery/nuclei #6398

## Issue Title
[BUG] Fuzzing templates skips numeric path parts

## Issue Description
### Is there an existing issue for this?

- [x] I have searched the existing issues.

### Current Behavior

Ref: https://github.com/projectdiscovery/nuclei/actions/runs/17080437183/job/48437074486?pr=6393 failing `integration_tests/fuzz/fuzz-path-sqli.yaml `

`dev` branch version skips some items in path based fuzzing:

```
mzack@MacBookPro nuclei % go run . -t  ../../integration_tests/fuzz/fuzz-path-sqli.yaml -l ../../integration_tests/fuzz/testData/ginandjuice.proxify.yaml -im yaml -verbose

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.8

                projectdiscovery.io

[VER] Started metrics server at localhost:9092
[INF] Current nuclei version: v3.4.8 (latest)
[INF] Current nuclei-templates version: v10.2.7 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 55
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 9
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/reset-password) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog/post%20OR%20True?postId=3&source=proxify
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/host-header-lab%20OR%20True
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog%20OR%20True/posts
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/user%20OR%20True/55/profile
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog/posts%20OR%20True
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog%20OR%20True/post?postId=3&source=proxify
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/user/55/profile
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/user/55/profile%20OR%20True
[INF] Scan completed in 51.435875ms. No results found.
```

`main` branch version correctly fuzzes all the path parts:
```
mzack@MacBookPro nuclei % go run . -t  ../../integration_tests/fuzz/fuzz-path-sqli.yaml -l ../../integration_tests/fuzz/testData/ginandjuice.proxify.yaml -im yaml -verbose

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.7

                projectdiscovery.io

[VER] Started metrics server at localhost:9092
[INF] Current nuclei version: v3.4.7 (latest)
[INF] Current nuclei-templates version: v10.2.7 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 55
[INF] Templates loaded for current scan: 1
[WRN] Loading 1 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 9
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/reset-password) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] fuzz: target(http://127.0.0.1:8082/user) not applicable for fuzzing
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/user%20OR%20True/55/profile
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog%20OR%20True/post?postId=3&source=proxify
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog%20OR%20True/posts
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/host-header-lab%20OR%20True
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog/post%20OR%20True?postId=3&source=proxify
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/blog/posts%20OR%20True
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/user/55%20OR%20True/profile
[path-based-sqli] [http] [info] http://127.0.0.1:8082/user/55%2520OR%2520True/profile [path:/user/55] [GET]
[VER] [path-based-sqli] Sent HTTP request to http://127.0.0.1:8082/user/55/profile%20OR%20True
[INF] Scan completed in 17.943209ms. 1 matches found.
```

### Expected Behavior

Correct fuzzing of all path items

### Steps To Reproduce

/

### Relevant log output

```shell

```

### Environment

```markdown
- OS: osx
- Nuclei: dev
- Go: 1.25
```

### Anything else?

Potentially something got altered in the fuzzing engine (or fuzzy playground) in latest PRs

## Repository Context
- **Workspace**: /mnt/data/bounty-workspaces/nuclei-6398
- **Build system**: go
- **Build command**: go build ./...
- **Test command**: go test ./...

## Testing Requirements
Before marking this task as complete, you MUST:
1. Implement the solution according to issue requirements
2. Ensure all existing tests pass
3. Add new tests if the issue requires new functionality
4. Follow the repository's code style and conventions
5. Create a git branch named: bounty-6398
6. Commit changes with clear messages

## Acceptance Criteria
{
  "feasible": true,
  "reason": null,
  "difficulty": 3,
  "estimatedHours": 6,
  "acceptanceCriteria": [
    "- [x] I have searched the existing issues."
  ],
  "testPlan": {
    "buildSystem": "go",
    "buildCmd": "go build ./...",
    "testCmd": "go test ./...",
    "ciFound": false,
    "nucleiValidation": false,
    "customChecks": []
  },
  "ciRequirements": null,
  "hasContributing": true,
  "workspaceDir": "/mnt/data/bounty-workspaces/nuclei-6398"
}

## Output
- Branch name: bounty-6398
- All changes committed and ready for testing
- Brief summary of what was changed

