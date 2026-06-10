# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOBUILD_OUTPUT := 
GOBUILD_OUTPUT_EXT := 
GOBUILD_PACKAGES := 
GOBUILD_ADDITIONAL_ARGS := 
GOMOD := $(GOCMD) mod
GOTEST := $(GOCMD) test
GOFLAGS := -v
GOFUZZ_PACKAGE ?=
FUZZ_DURATION ?= 15m
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
	LDFLAGS += -extldflags "-static"
endif

ifeq ($(shell go env GOOS),windows)
	GOBUILD_OUTPUT_EXT := .exe
endif

.PHONY: all build build-stats clean devtools-all devtools-bindgen devtools-scrapefuncs fuzz fuzz-ci fuzz-tools
.PHONY: devtools-tsgen docs docgen dsl-docs functional go-build lint lint-strict fuzzplayground syntax-docs
.PHONY: integration integration-debug jsupdate-all jsupdate-bindgen jsupdate-tsgen memogen scan-charts test test-with-lint
.PHONY: tidy ts verify download vet template-validate build-fuzz discover-fuzz-packages

all: build

clean:
	rm -f '${GOBUILD_OUTPUT}${GOBUILD_OUTPUT_EXT}' 2>/dev/null

go-build: clean
go-build:
	CGO_ENABLED=0 $(GOBUILD) -trimpath $(GOFLAGS) -ldflags '${LDFLAGS}' $(GOBUILD_ADDITIONAL_ARGS) \
		 -o '${GOBUILD_OUTPUT}${GOBUILD_OUTPUT_EXT}' $(GOBUILD_PACKAGES)

build: GOFLAGS = -pgo=auto
build: GOBUILD_OUTPUT = ./bin/nuclei
build: GOBUILD_PACKAGES = cmd/nuclei/main.go
build: go-build

build-test: GOFLAGS = -v -pgo=auto
build-test: GOBUILD_OUTPUT = ./bin/nuclei.test
build-test: GOBUILD_PACKAGES = ./cmd/nuclei/
build-test: clean
build-test:
	CGO_ENABLED=0 $(GOCMD) test -c -trimpath $(GOFLAGS) -ldflags '${LDFLAGS}' $(GOBUILD_ADDITIONAL_ARGS) \
		 -o '${GOBUILD_OUTPUT}${GOBUILD_OUTPUT_EXT}' ${GOBUILD_PACKAGES}

build-stats: GOBUILD_OUTPUT = ./bin/nuclei-stats
build-stats: GOBUILD_PACKAGES = cmd/nuclei/main.go
build-stats: GOBUILD_ADDITIONAL_ARGS = -tags=stats
build-stats: go-build

scan-charts: GOBUILD_OUTPUT = ./bin/scan-charts
scan-charts: GOBUILD_PACKAGES = cmd/scan-charts/main.go
scan-charts: go-build

template-signer: GOBUILD_OUTPUT = ./bin/template-signer
template-signer: GOBUILD_PACKAGES = cmd/tools/signer/main.go
template-signer: go-build

docgen: GOBUILD_OUTPUT = ./bin/docgen
docgen: GOBUILD_PACKAGES = cmd/docgen/docgen.go
docgen: bin = dstdocgen
docgen:
	@if ! which $(bin) >/dev/null; then \
		echo "Command $(bin) not found! Installing..."; \
		go install -v github.com/projectdiscovery/yamldoc-go/cmd/docgen/$(bin)@latest; \
	fi
	# TODO: FIX THIS PANIC
	$(GOCMD) generate pkg/templates/templates.go
	$(GOBUILD) -o "${GOBUILD_OUTPUT}" $(GOBUILD_PACKAGES)

docs: docgen
docs:
	./bin/docgen docs.md nuclei-jsonschema.json

syntax-docs: docgen
syntax-docs:
	./bin/docgen SYNTAX-REFERENCE.md nuclei-jsonschema.json

test: GOFLAGS = -race -v -timeout 1h -count 1
test:
	$(GOTEST) $(GOFLAGS) ./...

integration:
	$(GOTEST) -tags=integration -timeout 1h ./internal/tests/integration

integration-debug:
	$(GOTEST) -tags=integration ./internal/tests/integration -v $(GO_TEST_ARGS) -args $(INTEGRATION_ARGS)

functional: build
	@release_binary="$$(command -v nuclei.exe 2>/dev/null || command -v nuclei 2>/dev/null)"; \
	if [ -z "$$release_binary" ]; then \
		echo "release nuclei binary not found on PATH"; \
		exit 1; \
	fi; \
	RELEASE_BINARY="$$release_binary" DEV_BINARY="$(PWD)/bin/nuclei" \
		$(GOTEST) -tags=functional -timeout 1h ./internal/tests/functional

tidy:
	$(GOMOD) tidy

download:
	$(GOMOD) download

verify: download
	$(GOMOD) verify

vet: verify
	$(GOCMD) vet ./...

devtools-bindgen: GOBUILD_OUTPUT = ./bin/bindgen
devtools-bindgen: GOBUILD_PACKAGES = pkg/js/devtools/bindgen/cmd/bindgen/main.go
devtools-bindgen: go-build

devtools-tsgen: GOBUILD_OUTPUT = ./bin/tsgen
devtools-tsgen: GOBUILD_PACKAGES = pkg/js/devtools/tsgen/cmd/tsgen/main.go
devtools-tsgen: go-build

devtools-scrapefuncs: GOBUILD_OUTPUT = ./bin/scrapefuncs
devtools-scrapefuncs: GOBUILD_PACKAGES = pkg/js/devtools/scrapefuncs/main.go
devtools-scrapefuncs: go-build

devtools-all: devtools-bindgen devtools-tsgen devtools-scrapefuncs

jsupdate-bindgen: GOBUILD_OUTPUT = ./bin/bindgen
jsupdate-bindgen: GOBUILD_PACKAGES = pkg/js/devtools/bindgen/cmd/bindgen/main.go
jsupdate-bindgen: go-build
jsupdate-bindgen:
	./$(GOBUILD_OUTPUT) -dir pkg/js/libs -out pkg/js/generated

jsupdate-tsgen: GOBUILD_OUTPUT = ./bin/tsgen
jsupdate-tsgen: GOBUILD_PACKAGES = pkg/js/devtools/tsgen/cmd/tsgen/main.go
jsupdate-tsgen: go-build
jsupdate-tsgen:
	./$(GOBUILD_OUTPUT) -dir pkg/js/libs -out pkg/js/generated/ts

jsupdate-all: jsupdate-bindgen jsupdate-tsgen

ts: jsupdate-tsgen

fuzzplayground: GOBUILD_OUTPUT = ./bin/fuzzplayground
fuzzplayground: GOBUILD_PACKAGES = cmd/tools/fuzzplayground/main.go
fuzzplayground: LDFLAGS = -s -w
fuzzplayground: go-build

fuzz-tools:
	@$(GOCMD) tool -modfile=go.tool.mod -n go-fuzz-build >/dev/null
	@$(GOCMD) tool -modfile=go.tool.mod -n go-fuzz >/dev/null

discover-fuzz-packages:
	@set -eu; \
	entries_file="$$(mktemp)"; \
	trap 'rm -f "$$entries_file"' EXIT HUP INT TERM; \
	find . -type d -path '*/testdata/gofuzz-corpus' | LC_ALL=C sort | while IFS= read -r corpus_dir; do \
		pkg_dir="$${corpus_dir%/testdata/gofuzz-corpus}"; \
		if [ ! -f "$$pkg_dir/fuzz.go" ]; then \
			continue; \
		fi; \
		pkg_dir="$${pkg_dir#./}"; \
		pkg="./$$pkg_dir"; \
		if ! $(GOCMD) list "$$pkg" >/dev/null 2>&1; then \
			echo "failed to resolve $$pkg"; \
			exit 1; \
		fi; \
		jq -cn --arg pkg "$$pkg" '{pkg: $$pkg}' >> "$$entries_file"; \
	done; \
	if [ ! -s "$$entries_file" ]; then \
		echo "no fuzzable packages discovered"; \
		exit 1; \
	fi; \
	matrix="$$(jq -cs '{include: .}' "$$entries_file")"; \
	if [ -n "$${GITHUB_OUTPUT:-}" ]; then \
		printf 'matrix=%s\n' "$$matrix" >> "$${GITHUB_OUTPUT}"; \
	else \
		printf '%s\n' "$$matrix"; \
	fi

build-fuzz: fuzz-tools
	@if [ -z "$(GOFUZZ_PACKAGE)" ]; then echo "GOFUZZ_PACKAGE is required"; exit 1; fi
	@PACKAGE_DIR="$$( $(GOCMD) list -f '{{.Dir}}' $(GOFUZZ_PACKAGE) 2>/dev/null )" || { \
		echo "failed to resolve GOFUZZ_PACKAGE: $(GOFUZZ_PACKAGE)"; \
		exit 1; \
	}; \
	WORKDIR="$$PACKAGE_DIR/.gofuzz"; \
	CORPUS_DIR="$$PACKAGE_DIR/testdata/gofuzz-corpus"; \
	BIN_PATH="$$WORKDIR/$$(basename "$$PACKAGE_DIR")-fuzz.zip"; \
	if [ ! -d "$$CORPUS_DIR" ]; then \
		echo "seed corpus directory does not exist: $$CORPUS_DIR"; \
		exit 1; \
	fi; \
	set -- "$$CORPUS_DIR"/*; \
	if [ "$$1" = "$$CORPUS_DIR/*" ]; then \
		echo "seed corpus directory has no seed files: $$CORPUS_DIR"; \
		exit 1; \
	fi; \
	mkdir -p "$$WORKDIR/corpus"; \
	cp -f "$$CORPUS_DIR"/* "$$WORKDIR/corpus/"; \
	GO111MODULE=on $(GOCMD) tool -modfile=go.tool.mod go-fuzz-build -o "$$BIN_PATH" $(GOFUZZ_PACKAGE)

fuzz: build-fuzz
	@PACKAGE_DIR="$$( $(GOCMD) list -f '{{.Dir}}' $(GOFUZZ_PACKAGE) 2>/dev/null )" || { \
		echo "failed to resolve GOFUZZ_PACKAGE: $(GOFUZZ_PACKAGE)"; \
		exit 1; \
	}; \
	WORKDIR="$$PACKAGE_DIR/.gofuzz"; \
	BIN_PATH="$$WORKDIR/$$(basename "$$PACKAGE_DIR")-fuzz.zip"; \
	$(GOCMD) tool -modfile=go.tool.mod go-fuzz -bin="$$BIN_PATH" -workdir="$$WORKDIR"

fuzz-ci:
	@if [ "$${CI:-}" != "true" ]; then echo "fuzz-ci should be run in CI; use 'make fuzz' locally"; exit 1; fi
	@if [ -z "$(GOFUZZ_PACKAGE)" ]; then echo "GOFUZZ_PACKAGE is required"; exit 1; fi
	@set -eu; \
	pkg_dir="$(GOFUZZ_PACKAGE)"; \
	pkg_dir="$${pkg_dir#./}"; \
	workdir="$$pkg_dir/.gofuzz"; \
	pkg_id="$$(printf '%s' "$$pkg_dir" | tr '/.' '-')"; \
	artifact_name="gofuzz-$$pkg_id"; \
	if [ -n "$${GITHUB_OUTPUT:-}" ]; then \
		printf 'artifact_name=%s\n' "$$artifact_name" >> "$${GITHUB_OUTPUT}"; \
	fi; \
	mkdir -p "$$workdir"; \
	timeout_bin="$$(command -v timeout || command -v gtimeout || true)"; \
	if [ -z "$$timeout_bin" ]; then \
		echo "timeout command not found"; \
		exit 1; \
	fi; \
	exit_code=0; \
	"$$timeout_bin" "$(FUZZ_DURATION)" $(MAKE) --no-print-directory fuzz GOFUZZ_PACKAGE="$(GOFUZZ_PACKAGE)" || exit_code=$$?; \
	if [ "$$exit_code" -ne 0 ] && [ "$$exit_code" -ne 124 ]; then \
		echo "fuzzing failed with exit code $$exit_code"; \
		exit "$$exit_code"; \
	fi; \
	count_files() { \
		dir="$$1"; \
		if [ ! -d "$$dir" ]; then \
			echo 0; \
			return; \
		fi; \
		if [ "$$(basename "$$dir")" = "crashers" ]; then \
			find "$$dir" -maxdepth 1 -type f -printf '%f\n' | sed -E 's/\.(output|quoted)$$//' | sort -u | wc -l | tr -d '[:space:]'; \
			return; \
		fi; \
		find "$$dir" -maxdepth 1 -type f | wc -l | tr -d '[:space:]'; \
	}; \
	crasher_count="$$(count_files "$$workdir/crashers")"; \
	corpus_count="$$(count_files "$$workdir/corpus")"; \
	suppressions_count="$$(count_files "$$workdir/suppressions")"; \
	if [ -n "$${GITHUB_STEP_SUMMARY:-}" ]; then \
		{ \
			echo "## \`$(GOFUZZ_PACKAGE)\`"; \
			echo; \
			echo "- Corpus: $$corpus_count"; \
			echo "- Crashers: $$crasher_count"; \
			echo "- Suppressions: $$suppressions_count"; \
			echo; \
		} >> "$${GITHUB_STEP_SUMMARY}"; \
	else \
		printf 'Package: %s\nCorpus: %s\nCrashers: %s\nSuppressions: %s\n' "$(GOFUZZ_PACKAGE)" "$$corpus_count" "$$crasher_count" "$$suppressions_count"; \
	fi

memogen: GOBUILD_OUTPUT = ./bin/memogen
memogen: GOBUILD_PACKAGES = cmd/memogen/memogen.go
memogen: go-build
memogen:
	./$(GOBUILD_OUTPUT) -src pkg/js/libs -tpl cmd/memogen/function.tpl

dsl-docs: GOBUILD_OUTPUT = ./bin/scrapefuncs
dsl-docs: GOBUILD_PACKAGES = pkg/js/devtools/scrapefuncs/main.go
dsl-docs:
	./$(GOBUILD_OUTPUT) -out dsl.md

template-validate: build
template-validate:
	./bin/nuclei -ut
	./bin/nuclei -validate \
		-et http/technologies \
		-t dns \
		-t ssl \
		-t network \
		-t http/exposures \
		-ept code
	./bin/nuclei -validate \
		-w workflows \
		-et http/technologies \
		-ept code