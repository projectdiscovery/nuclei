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
	LDFLAGS += -extldflags "-static"
endif
    
.PHONY: all build build-stats clean devtools-all devtools-bindgen devtools-scrapefuncs
.PHONY: devtools-tsgen docs docgen dsl-docs functional fuzzplayground go-build syntax-docs
.PHONY: integration jsupdate-all jsupdate-bindgen jsupdate-tsgen memogen scan-charts test 
.PHONY: tidy ts verify download vet template-validate

all: build

clean:
	rm -f '${GOBUILD_OUTPUT}' 2>/dev/null

go-build: clean
go-build:
	CGO_ENABLED=0 $(GOBUILD) -trimpath $(GOFLAGS) -ldflags '${LDFLAGS}' $(GOBUILD_ADDITIONAL_ARGS) \
		 -o '${GOBUILD_OUTPUT}' $(GOBUILD_PACKAGES)

build: GOFLAGS = -v -pgo=auto
build: GOBUILD_OUTPUT = ./bin/nuclei
build: GOBUILD_PACKAGES = cmd/nuclei/main.go
build: go-build

build-test: GOFLAGS = -v -pgo=auto
build-test: GOBUILD_OUTPUT = ./bin/nuclei.test
build-test: GOBUILD_PACKAGES = ./cmd/nuclei/
build-test: clean
build-test:
	CGO_ENABLED=0 $(GOCMD) test -c -trimpath $(GOFLAGS) -ldflags '${LDFLAGS}' $(GOBUILD_ADDITIONAL_ARGS) \
		 -o '${GOBUILD_OUTPUT}' ${GOBUILD_PACKAGES}

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

test: GOFLAGS = -race -v
test:
	$(GOTEST) $(GOFLAGS) ./...

integration:
	cd integration_tests; bash run.sh

functional:
	cd cmd/functional-test; bash run.sh

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
	./bin/nuclei -validate -et http/technologies
	./bin/nuclei -validate -w workflows -et http/technologies