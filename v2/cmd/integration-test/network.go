package main

import (
	"net"

	"github.com/projectdiscovery/nuclei/v2/internal/testutils"
)

var networkTestcases = map[string]testutils.TestCase{
	"network/basic.yaml":      &networkBasic{},
	"network/hex.yaml":        &networkBasic{},
	"network/multi-step.yaml": &networkMultiStep{},
}

type networkBasic struct{}

// Executes executes a test case and returns an error if occurred
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

	results, err := testutils.RunNucleiAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}

type networkMultiStep struct{}

// Executes executes a test case and returns an error if occurred
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

	results, err := testutils.RunNucleiAndGetResults(filePath, ts.URL, debug)
	if err != nil {
		return err
	}
	if routerErr != nil {
		return routerErr
	}
	if len(results) != 1 {
		return errIncorrectResultsCount(results)
	}
	return nil
}
