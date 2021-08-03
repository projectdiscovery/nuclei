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
		$(GOCMD) generate pkg/templates/templates.go
		$(GOBUILD) -o "cmd/docgen/docgen" cmd/docgen/docgen.go 
		./cmd/docgen/docgen docs.md
test: 
		$(GOTEST) -v ./...
tidy:
		$(GOMOD) tidy