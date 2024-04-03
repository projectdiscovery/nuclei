package compiler

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/cruisecontrol"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestNewCompilerConsoleDebug(t *testing.T) {
	gotString := ""
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	gologger.DefaultLogger.SetWriter(&noopWriter{
		Callback: func(data []byte, level levels.Level) {
			gotString = string(data)
		},
	})

	cc, err := cruisecontrol.New(cruisecontrol.ParseOptionsFrom(types.DefaultOptions()))
	require.Nil(t, err)

	compiler, err := New(cc)
	require.Nil(t, err)
	_, err = compiler.Execute("console.log('hello world');", NewExecuteArgs())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotString, "hello world") {
		t.Fatalf("console.log not working, got=%v", gotString)
	}
}

func TestExecuteResultGetSuccess(t *testing.T) {
	cc, err := cruisecontrol.New(cruisecontrol.ParseOptionsFrom(types.DefaultOptions()))
	require.Nil(t, err)
	compiler, err := New(cc)
	require.Nil(t, err)
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
