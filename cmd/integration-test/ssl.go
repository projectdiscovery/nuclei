package main

import (
	"crypto/tls"
	"net"

	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

var sslTestcases = []TestCaseInfo{
	{Path: "protocols/ssl/basic.yaml", TestCase: &sslBasic{}},
	{Path: "protocols/ssl/basic-ztls.yaml", TestCase: &sslBasicZtls{}},
	{Path: "protocols/ssl/custom-cipher.yaml", TestCase: &sslCustomCipher{}},
	{Path: "protocols/ssl/custom-version.yaml", TestCase: &sslCustomVersion{}},
	{Path: "protocols/ssl/ssl-with-vars.yaml", TestCase: &sslWithVars{}},
	{Path: "protocols/ssl/multi-req.yaml", TestCase: &sslMultiReq{}},
}

type sslBasic struct{}

// Execute executes a test case and returns an error if occurred
func (h *sslBasic) Execute(filePath string) error {
	ts := testutils.NewTCPServer(&tls.Config{}, defaultStaticPort, func(conn net.Conn) {
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
	ts := testutils.NewTCPServer(&tls.Config{}, defaultStaticPort, func(conn net.Conn) {
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

type sslCustomCipher struct{}

// Execute executes a test case and returns an error if occurred
func (h *sslCustomCipher) Execute(filePath string) error {
	ts := testutils.NewTCPServer(&tls.Config{CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256}}, defaultStaticPort, func(conn net.Conn) {
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

type sslCustomVersion struct{}

// Execute executes a test case and returns an error if occurred
func (h *sslCustomVersion) Execute(filePath string) error {
	ts := testutils.NewTCPServer(&tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, defaultStaticPort, func(conn net.Conn) {
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

type sslWithVars struct{}

func (h *sslWithVars) Execute(filePath string) error {
	ts := testutils.NewTCPServer(&tls.Config{}, defaultStaticPort, func(conn net.Conn) {
		defer conn.Close()
		data := make([]byte, 4)
		if _, err := conn.Read(data); err != nil {
			return
		}
	})
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-V", "test=asdasdas")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 1)
}

type sslMultiReq struct{}

func (h *sslMultiReq) Execute(filePath string) error {
	//nolint:staticcheck // SSLv3 is intentionally used for testing purposes
	ts := testutils.NewTCPServer(&tls.Config{
		MinVersion: tls.VersionSSL30,
		MaxVersion: tls.VersionTLS11,
	}, defaultStaticPort, func(conn net.Conn) {
		defer conn.Close()
		data := make([]byte, 4)
		if _, err := conn.Read(data); err != nil {
			return
		}
	})
	defer ts.Close()

	results, err := testutils.RunNucleiTemplateAndGetResults(filePath, ts.URL, debug, "-V")
	if err != nil {
		return err
	}

	return expectResultsCount(results, 2)
}
