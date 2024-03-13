package main

import (
	"flag"

	_ "github.com/mattn/go-sqlite3"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils/fuzzplayground"
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
