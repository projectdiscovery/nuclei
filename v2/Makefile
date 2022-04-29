# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v
# This should be disabled if the binary uses pprof
LDFLAGS := -s -w

ifneq ($(shell go env GOOS),darwin)
LDFLAGS := -extldflags "-static"
endif
    
all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "nuclei" cmd/nuclei/main.go
docs:
	if ! which dstdocgen > /dev/null; then
		echo -e "Command not found! Install? (y/n) \c"
		go get -v github.com/projectdiscovery/yamldoc-go/cmd/docgen/dstdocgen
	fi
	$(GOCMD) generate pkg/templates/templates.go
	$(GOBUILD) -o "cmd/docgen/docgen" cmd/docgen/docgen.go
	./cmd/docgen/docgen docs.md nuclei-jsonschema.json
test:
	$(GOTEST) $(GOFLAGS) ./...
integration:
	bash ../integration_tests/run.sh
functional:
	bash cmd/functional-tests/run.sh
tidy:
	$(GOMOD) tidy