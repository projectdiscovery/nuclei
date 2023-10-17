package main

import (
	"net"
	"strings"

	"github.com/gobwas/ws/wsutil"

	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var websocketTestCases = []TestCaseInfo{
	{Path: "protocols/websocket/basic.yaml", TestCase: &websocketBasic{}},
	{Path: "protocols/websocket/cswsh.yaml", TestCase: &websocketCswsh{}},
	{Path: "protocols/websocket/no-cswsh.yaml", TestCase: &websocketNoCswsh{}},
	{Path: "protocols/websocket/path.yaml", TestCase: &websocketWithPath{}},
}

type websocketBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *websocketBasic) Execute(filePath string) error {
	connHandler := func(conn net.Conn) {
		for {
			msg, op, _ := wsutil.ReadClientData(conn)
			if string(msg) != "hello" {
				return
			}
			_ = wsutil.WriteServerMessage(conn, op, []byte("world"))
		}
	}
	originValidate := func(origin string) bool {
		return true
	}
	ts := testutils.NewWebsocketServer("", connHandler, originValidate)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, strings.ReplaceAll(ts.URL, "http", "ws"), debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type websocketCswsh struct{}

// Execute executes a test case and returns an error if occurred
func (h *websocketCswsh) Execute(filePath string) error {
	connHandler := func(conn net.Conn) {

	}
	originValidate := func(origin string) bool {
		return true
	}
	ts := testutils.NewWebsocketServer("", connHandler, originValidate)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, strings.ReplaceAll(ts.URL, "http", "ws"), debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type websocketNoCswsh struct{}

// Execute executes a test case and returns an error if occurred
func (h *websocketNoCswsh) Execute(filePath string) error {
	connHandler := func(conn net.Conn) {

	}
	originValidate := func(origin string) bool {
		return origin == "https://google.com"
	}
	ts := testutils.NewWebsocketServer("", connHandler, originValidate)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, strings.ReplaceAll(ts.URL, "http", "ws"), debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 0)
}

type websocketWithPath struct{}

// Execute executes a test case and returns an error if occurred
func (h *websocketWithPath) Execute(filePath string) error {
	connHandler := func(conn net.Conn) {

	}
	originValidate := func(origin string) bool {
		return origin == "https://google.com"
	}
	ts := testutils.NewWebsocketServer("/test", connHandler, originValidate)
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, strings.ReplaceAll(ts.URL, "http", "ws"), debug)
	if err != nil {
		return err
	}

	return expectResultsCount(results, 0)
}
