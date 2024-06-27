package compiler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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
	p, err := WrapScriptNCompile("console.log('hello world');", false)
	if err != nil {
		t.Fatal(err)
	}

	_, err = compiler.ExecuteWithOptions(p, NewExecuteArgs(), &ExecuteOptions{Context: context.Background(),
		Timeout:         20,
		TimeoutVariants: types.TimeoutVariants{JsCompilerExecutionTimeout: time.Duration(20) * time.Second}},
	)
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
