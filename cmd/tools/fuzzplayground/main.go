package main

import (
	"flag"

	"github.com/effluxio/nuclei/v3/pkg/testutils/fuzzplayground"
	_ "github.com/mattn/go-sqlite3"
	"github.com/projectdiscovery/gologger"
)

var (
	addr string
)

func main() {
	flag.StringVar(&addr, "addr", "localhost:8082", "playground server address")
	flag.Parse()

	defer fuzzplayground.Cleanup()
	server := fuzzplayground.GetPlaygroundServer()
	defer server.Close()

	// Start the server
	if err := server.Start(addr); err != nil {
		gologger.Fatal().Msgf("Could not start server: %s\n", err)
	}
}
