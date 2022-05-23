package main

import (
	"net"
	"strings"

	"github.com/gobwas/ws/wsutil"

	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

var websocketTestCases = map[string]testutils.TestCase{
	"websocket/basic.yaml":    &websocketBasic{},
	"websocket/cswsh.yaml":    &websocketCswsh{},
	"websocket/no-cswsh.yaml": &websocketNoCswsh{},
	"websocket/path.yaml":     &websocketWithPath{},
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
