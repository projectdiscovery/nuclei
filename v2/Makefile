# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
    
all: build
build:
	$(GOBUILD) -v -ldflags="-extldflags=-static" -o "nuclei" cmd/nuclei/main.go
docs:
	if ! which dstdocgen > /dev/null; then
		echo -e "Command not found! Install? (y/n) \c"
		go get -v github.com/projectdiscovery/yamldoc-go/cmd/docgen/dstdocgen
	fi
	$(GOCMD) generate pkg/templates/templates.go
	$(GOBUILD) -o "cmd/docgen/docgen" cmd/docgen/docgen.go
	./cmd/docgen/docgen docs.md nuclei-jsonschema.json
test:
	$(GOTEST) -v ./...
integration:
	bash ../integration_tests/run.sh
functional:
	bash cmd/functional-tests/run.sh
tidy:
	$(GOMOD) tidy