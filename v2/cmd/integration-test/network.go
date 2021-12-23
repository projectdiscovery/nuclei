package main

import (
	"net"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var networkTestcases = map[string]testutils.TestCase{
	"network/basic.yaml":          &networkBasic{},
	"network/hex.yaml":            &networkBasic{},
	"network/multi-step.yaml":     &networkMultiStep{},
	"network/self-contained.yaml": &networkRequestSelContained{},
}

const defaultStaticPort = 5431

type networkBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *networkBasic) Execute(filePath string) error {
	var routerErr error

	ts := testutils.NewTCPServer(func(conn net.Conn) {
		defer conn.Close()

		data := make([]byte, 4)
		if _, err := conn.Read(data); err != nil {
			routerErr = err
			return
		}
		if string(data) == "PING" {
			_, _ = conn.Write([]byte("PONG"))
		}
	})
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}

type networkMultiStep struct{}

// Execute executes a test case and returns an error if occurred
func (h *networkMultiStep) Execute(filePath string) error {
	var routerErr error

	ts := testutils.NewTCPServer(func(conn net.Conn) {
		defer conn.Close()

		data := make([]byte, 5)
		if _, err := conn.Read(data); err != nil {
			routerErr = err
			return
		}
		if string(data) == "FIRST" {
			_, _ = conn.Write([]byte("PING"))
		}

		data = make([]byte, 6)
		if _, err := conn.Read(data); err != nil {
			routerErr = err
			return
		}
		if string(data) == "SECOND" {
			_, _ = conn.Write([]byte("PONG"))
		}
		_, _ = conn.Write([]byte("NUCLEI"))
	})
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	var expectedResultsSize int
	if debug {
		expectedResultsSize = 3
	} else {
		expectedResultsSize = 1
	}

	return expectResultsCount(results, expectedResultsSize)
}

type networkRequestSelContained struct{}

// Execute executes a test case and returns an error if occurred
func (h *networkRequestSelContained) Execute(filePath string) error {
	var routerErr error

	ts := testutils.NewTCPServer(func(conn net.Conn) {
		defer conn.Close()

		_, _ = conn.Write([]byte("Authentication successful"))
	}, defaultStaticPort)
	defer ts.Close()
	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, "", debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}

	return expectResultsCount(results, 1)
}
