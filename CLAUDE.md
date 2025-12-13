# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Nuclei is a modern, high-performance vulnerability scanner built in Go that leverages YAML-based templates for customizable vulnerability detection. It supports multiple protocols (HTTP, DNS, TCP, SSL, WebSocket, WHOIS, JavaScript, Code) and is designed for zero false positives through real-world condition simulation.

## Development Commands

### Building and Testing
- `make build` - Build the main nuclei binary to ./bin/nuclei
- `make test` - Run unit tests with race detection
- `make integration` - Run integration tests (builds and runs test suite)
- `make functional` - Run functional tests
- `make vet` - Run go vet for code analysis
- `make tidy` - Clean up go modules

### Validation and Linting
- `make template-validate` - Validate nuclei templates using the built binary
- `go fmt ./...` - Format Go code
- `go vet ./...` - Static analysis

### Development Tools
- `make devtools-all` - Build all development tools (bindgen, tsgen, scrapefuncs)
- `make jsupdate-all` - Update JavaScript bindings and TypeScript definitions
- `make docs` - Generate documentation
- `make memogen` - Generate memoization code for JavaScript libraries

### Testing Specific Components
- Run single test: `go test -v ./pkg/path/to/package -run TestName`
- Integration tests are in `integration_tests/` and can be run via `make integration`

## Architecture Overview

### Core Components
- **cmd/nuclei** - Main CLI entry point with flag parsing and configuration
- **internal/runner** - Core runner that orchestrates the entire scanning process
- **pkg/core** - Execution engine with work pools and template clustering
- **pkg/templates** - Template parsing, compilation, and management
- **pkg/protocols** - Protocol implementations (HTTP, DNS, Network, etc.)
- **pkg/operators** - Matching and extraction logic (matchers/extractors)
- **pkg/catalog** - Template discovery and loading from disk/remote sources

### Protocol Architecture
Each protocol (HTTP, DNS, Network, etc.) implements:
- Request interface with Compile(), ExecuteWithResults(), Match(), Extract() methods
- Operators embedding for matching/extraction functionality
- Protocol-specific request building and execution logic

### Template System
- Templates are YAML files defining vulnerability detection logic
- Compiled into executable requests with operators (matchers/extractors)
- Support for workflows (multistep template execution)
- Template clustering optimizes identical requests across multiple templates

### Key Execution Flow
1. Template loading and compilation via pkg/catalog/loader
2. Input provider setup for targets
3. Engine creation with work pools for concurrency
4. Template execution with result collection via operators
5. Output writing and reporting integration

### JavaScript Integration
- Custom JavaScript runtime for code protocol templates
- Auto-generated bindings in pkg/js/generated/
- Library implementations in pkg/js/libs/
- Development tools for binding generation in pkg/js/devtools/

## Template Development
- Templates located in separate nuclei-templates repository
- YAML format with info, requests, and operators sections  
- Support for multiple protocol types in single template
- Built-in DSL functions for dynamic content generation
- Template validation available via `make template-validate`

## Key Directories
- **lib/** - SDK for embedding nuclei as a library
- **examples/** - Usage examples for different scenarios
- **integration_tests/** - Integration test suite with protocol-specific tests
- **pkg/fuzz/** - Fuzzing engine and DAST capabilities
- **pkg/input/** - Input processing for various formats (Burp, OpenAPI, etc.)
- **pkg/reporting/** - Result export and issue tracking integrations