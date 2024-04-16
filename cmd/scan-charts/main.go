package main

import (
	"flag"

	"github.com/projectdiscovery/nuclei/v3/pkg/scan/charts"
)

var (
	dir     string
	address string
	output  string
)

func main() {
	flag.StringVar(&dir, "dir", "", "directory to scan")
	flag.StringVar(&address, "address", ":9000", "address to run the server on")
	flag.StringVar(&output, "output", "", "output filename of generated html file")
	flag.Parse()

	if dir == "" {
		flag.Usage()
		return
	}

	server, err := charts.NewScanEventsCharts(dir)
	if err != nil {
		panic(err)
	}
	server.PrintInfo()

	if output != "" {
		if err = server.GenerateHTML(output); err != nil {
			panic(err)
		}
		return
	}

	server.Start(address)
}
