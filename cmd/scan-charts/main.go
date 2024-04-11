package main

import (
	"flag"

	"github.com/projectdiscovery/nuclei/v3/pkg/scan/charts"
)

var (
	dir     string
	address string
)

func main() {
	flag.StringVar(&dir, "dir", "", "directory to scan")
	flag.StringVar(&address, "address", ":9000", "address to run the server on")
	flag.Parse()

	server, err := charts.NewScanEventsCharts(dir)
	if err != nil {
		panic(err)
	}
	server.PrintInfo()
	server.Start(address)
}
