package compiler

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

func TestNewCompilerConsoleDebug(t *testing.T) {
	gotString := ""
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	gologger.DefaultLogger.SetWriter(&noopWriter{
		Callback: func(data []byte, level levels.Level) {
			gotString = string(data)
		},
	})

	compiler := New()
	_, err := compiler.Execute("console.log('hello world');", NewExecuteArgs())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotString, "hello world") {
		t.Fatalf("console.log not working, got=%v", gotString)
	}
}

func TestExecuteResultGetSuccess(t *testing.T) {
	compiler := New()
	result, err := compiler.Execute("1+1 == 2", NewExecuteArgs())
	if err != nil {
		t.Fatal(err)
	}
	if result.GetSuccess() != true {
		t.Fatalf("expected true, got=%v", result.GetSuccess())
	}
}

type noopWriter struct {
	Callback func(data []byte, level levels.Level)
}

func (n *noopWriter) Write(data []byte, level levels.Level) {
	if n.Callback != nil {
		n.Callback(data, level)
	}
}
