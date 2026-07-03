package tsch

import (
	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
)

// Auth exposes Task Scheduler authentication constructors.
var Auth = goexec.AuthConstructors()

// Client is a GoExec-backed Task Scheduler execution client.
type Client struct {
	target  string
	auth    *goexec.Auth
	options goexec.ExecutionOptions
	nj      *utils.NucleiJS
}

// NewClient constructs a Task Scheduler client.
//
// Constructor: constructor(target: string, auth: any)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	nj := utils.NewNucleiJS(runtime)
	nj.ObjectSig = "Client(target, auth)"
	client := &Client{options: goexec.DefaultExecutionOptions(), nj: nj}
	client.target, _ = nj.GetArg(call.Arguments, 0).(string)
	if auth, ok := nj.GetArg(call.Arguments, 1).(*goexec.Auth); ok {
		client.auth = auth
	} else {
		nj.Throw("auth must be created with tsch.Auth")
	}
	obj := runtime.NewObject()
	client.bindAliases(obj, runtime)
	return obj
}

// SetOptions updates default execution options for future client calls.
func (c *Client) SetOptions(opts interface{}) {
	c.options = goexec.MergeOptions(c.options, opts)
}

// Demand registers and demand-runs a temporary scheduled task.
func (c *Client) Demand(taskName string, executable string, args string, opts interface{}) map[string]interface{} {
	return c.run("demand", taskName, executable, args, opts)
}

// Create registers a scheduled task and starts it according to GoExec defaults.
func (c *Client) Create(taskName string, executable string, args string, opts interface{}) map[string]interface{} {
	return c.run("create", taskName, executable, args, opts)
}

func (c *Client) bindAliases(obj *goja.Object, runtime *goja.Runtime) {
	_ = obj.Set("setOptions", func(call goja.FunctionCall) goja.Value {
		c.SetOptions(exportArg(call, 0))
		return goja.Undefined()
	})
	_ = obj.Set("SetOptions", func(call goja.FunctionCall) goja.Value {
		c.SetOptions(exportArg(call, 0))
		return goja.Undefined()
	})
	_ = obj.Set("demand", func(call goja.FunctionCall) goja.Value {
		taskName, _ := exportArg(call, 0).(string)
		executable, _ := exportArg(call, 1).(string)
		args, _ := exportArg(call, 2).(string)
		return runtime.ToValue(c.Demand(taskName, executable, args, exportArg(call, 3)))
	})
	_ = obj.Set("Demand", func(call goja.FunctionCall) goja.Value {
		taskName, _ := exportArg(call, 0).(string)
		executable, _ := exportArg(call, 1).(string)
		args, _ := exportArg(call, 2).(string)
		return runtime.ToValue(c.Demand(taskName, executable, args, exportArg(call, 3)))
	})
	_ = obj.Set("create", func(call goja.FunctionCall) goja.Value {
		taskName, _ := exportArg(call, 0).(string)
		executable, _ := exportArg(call, 1).(string)
		args, _ := exportArg(call, 2).(string)
		return runtime.ToValue(c.Create(taskName, executable, args, exportArg(call, 3)))
	})
	_ = obj.Set("Create", func(call goja.FunctionCall) goja.Value {
		taskName, _ := exportArg(call, 0).(string)
		executable, _ := exportArg(call, 1).(string)
		args, _ := exportArg(call, 2).(string)
		return runtime.ToValue(c.Create(taskName, executable, args, exportArg(call, 3)))
	})
}

func (c *Client) run(method string, taskName string, executable string, args string, opts interface{}) map[string]interface{} {
	req := goexec.Request{
		Module:     "tsch",
		Method:     method,
		Target:     c.target,
		Auth:       c.auth,
		TaskName:   taskName,
		Executable: executable,
		Args:       args,
		Options:    goexec.MergeOptions(c.options, opts),
	}
	return goexec.Run(goexec.WithExecutionID(c.nj.Context(), c.nj.ExecutionId()), req).Public()
}

func exportArg(call goja.FunctionCall, index int) interface{} {
	if index >= len(call.Arguments) || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		return nil
	}
	return call.Arguments[index].Export()
}
