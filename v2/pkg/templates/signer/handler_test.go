package signer

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

// This Unit Test generates a new key pair and parses it
// to ensure that the key handler works as expected.
func TestKeyHandler(t *testing.T) {
	if val := os.Getenv("KEY_HANDLER_CI"); val != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestKeyHandler$", "-test.v")
		cmd.Env = append(cmd.Env, "KEY_HANDLER_CI=1")
		var buff bytes.Buffer
		cmd.Stdin = &buff
		buff.WriteString("CIUSER\n")
		buff.WriteString("\n")
		out, err := cmd.CombinedOutput()
		if !strings.Contains(string(out), "PASS\n") || err != nil {
			t.Fatalf("%s\n(exit status %v)", string(out), err)
		}
		return
	}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	h := &KeyHandler{}
	noUserPassphrase = true
	h.GenerateKeyPair()
	if h.UserCert == nil {
		t.Fatal("no user cert found")
	}
	if h.PrivateKey == nil {
		t.Fatal("no private key found")
	}

	// now parse the cert and private key
	if err := h.ParseUserCert(); err != nil {
		t.Fatal(err)
	}
	if err := h.ParsePrivateKey(); err != nil {
		t.Fatal(err)
	}
	if h.ecdsaKey == nil {
		t.Fatal("no ecdsa key found")
	}
	if h.ecdsaPubKey == nil {
		t.Fatal("no ecdsa public key found")
	}
	if h.cert == nil {
		t.Fatal("no certificate found")
	}
	if h.cert.Subject.CommonName != "CIUSER" {
		t.Fatal("invalid user name found")
	}
}
