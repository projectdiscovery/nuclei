# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOBUILD_OUTPUT := 
GOBUILD_PACKAGES := 
GOBUILD_ADDITIONAL_ARGS := 
GOMOD := $(GOCMD) mod
GOTEST := $(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
	LDFLAGS = -extldflags "-static"
endif
    
.PHONY: all build build-stats clean devtools-all devtools-bindgen devtools-scrapefuncs
.PHONY: devtools-tsgen docs dsl-docs functional fuzzplayground go-build integration
.PHONY: jsupdate-all jsupdate-bindgen jsupdate-tsgen memogen scan-charts test tidy ts verify

all: build

clean:
	@rm -f '${GOBUILD_OUTPUT}' 2>/dev/null

go-build: clean
go-build:
	$(GOBUILD) $(GOFLAGS) -ldflags '${LDFLAGS}' $(GOBUILD_ADDITIONAL_ARGS) \
		 -o '${GOBUILD_OUTPUT}' $(GOBUILD_PACKAGES)

build: GOBUILD_OUTPUT = ./bin/nuclei
build: GOBUILD_PACKAGES = cmd/nuclei/main.go
build: go-build

build-stats: GOBUILD_OUTPUT = ./bin/nuclei-stats
build-stats: GOBUILD_PACKAGES = cmd/nuclei/main.go
build-stats: GOBUILD_ADDITIONAL_ARGS = -tags=stats
build-stats: go-build

scan-charts: GOBUILD_OUTPUT = ./bin/scan-charts
scan-charts: GOBUILD_PACKAGES = cmd/scan-charts/main.go
scan-charts: go-build

docs: GOBUILD_OUTPUT = ./bin/docgen
docs: GOBUILD_PACKAGES = cmd/docgen/docgen.go
docs: bin = dstdocgen
docs:
	@if ! which $(bin) >/dev/null; then \
		read -p "${bin} not found. Do you want to install it? (y/n) " answer; \
		if [ "$$answer" = "y" ]; then \
			echo "Installing ${bin}..."; \
			go get -v github.com/projectdiscovery/yamldoc-go/cmd/docgen/$(bin); \
			go install -v github.com/projectdiscovery/yamldoc-go/cmd/docgen/$(bin); \
		else \
			echo "Please install ${bin} manually."; \
			exit 1; \
		fi \
	fi

	# TODO: Handle the panic, so that we just need to run `go install $(bin)@latest` (line 51-52)
	$(GOCMD) generate pkg/templates/templates.go

	$(GOBUILD) -o "${GOBUILD_OUTPUT}" $(GOBUILD_PACKAGES)
	./$(GOBUILD_OUTPUT) docs.md nuclei-jsonschema.json

	git reset --hard # line 59

test: GOFLAGS = -race -v
test:
	$(GOTEST) $(GOFLAGS) ./...

integration:
	cd integration_tests; bash run.sh

functional:
	cd cmd/functional-test; bash run.sh

tidy:
	$(GOMOD) tidy

verify: tidy
	$(GOMOD) verify

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

memogen: GOBUILD_OUTPUT = ./bin/memogen
memogen: GOBUILD_PACKAGES = cmd/memogen/memogen.go
memogen: go-build
memogen:
	./$(GOBUILD_OUTPUT) -src pkg/js/libs -tpl cmd/memogen/function.tpl

dsl-docs: GOBUILD_OUTPUT = ./bin/scrapefuncs
dsl-docs: GOBUILD_PACKAGES = pkg/js/devtools/scrapefuncs/main.go
dsl-docs:
	./$(GOBUILD_OUTPUT) -out dsl.md
