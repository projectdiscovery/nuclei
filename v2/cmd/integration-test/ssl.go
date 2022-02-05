package main

import (
	"net"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var sslTestcases = map[string]testutils.TestCase{
	"ssl/basic.yaml":      &sslBasic{},
	"ssl/basic-ztls.yaml": &sslBasicZtls{},
}

type sslBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *sslBasic) Execute(filePath string) error {
	ts := testutils.NewTCPServer(true, defaultStaticPort, func(conn net.Conn) {
		defer conn.Close()
		data := make([]byte, 4)
		if _, err := conn.Read(data); err != nil {
			return
		}
	})
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type sslBasicZtls struct{}

// Execute executes a test case and returns an error if occurred
func (h *sslBasicZtls) Execute(filePath string) error {
	ts := testutils.NewTCPServer(true, defaultStaticPort, func(conn net.Conn) {
		defer conn.Close()
		data := make([]byte, 4)
		if _, err := conn.Read(data); err != nil {
			return
		}
	})
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-ztls")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}
