package scmr

import (
	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
)

// Auth exposes SCMR authentication constructors.
var Auth = goexec.AuthConstructors()

// Client is a GoExec-backed SCMR execution client.
type Client struct {
	target  string
	auth    *goexec.Auth
	options goexec.ExecutionOptions
	nj      *utils.NucleiJS
}

// NewClient constructs an SCMR client.
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
		nj.Throw("auth must be created with scmr.Auth")
	}
	obj := runtime.NewObject()
	client.bindAliases(obj, runtime)
	return obj
}

// SetOptions updates default execution options for future client calls.
func (c *Client) SetOptions(opts interface{}) {
	c.options = goexec.MergeOptions(c.options, opts)
}

// Create creates, starts, and cleans up a temporary service.
func (c *Client) Create(serviceName string, executablePath string, args string, opts interface{}) map[string]interface{} {
	req := goexec.Request{
		Module:      "scmr",
		Method:      "create",
		Target:      c.target,
		Auth:        c.auth,
		ServiceName: serviceName,
		Executable:  executablePath,
		Args:        args,
		Options:     goexec.MergeOptions(c.options, opts),
	}
	return goexec.Run(goexec.WithExecutionID(c.nj.Context(), c.nj.ExecutionId()), req).Public()
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
	_ = obj.Set("create", func(call goja.FunctionCall) goja.Value {
		serviceName, _ := exportArg(call, 0).(string)
		executable, _ := exportArg(call, 1).(string)
		args, _ := exportArg(call, 2).(string)
		return runtime.ToValue(c.Create(serviceName, executable, args, exportArg(call, 3)))
	})
	_ = obj.Set("Create", func(call goja.FunctionCall) goja.Value {
		serviceName, _ := exportArg(call, 0).(string)
		executable, _ := exportArg(call, 1).(string)
		args, _ := exportArg(call, 2).(string)
		return runtime.ToValue(c.Create(serviceName, executable, args, exportArg(call, 3)))
	})
}

func exportArg(call goja.FunctionCall, index int) interface{} {
	if index >= len(call.Arguments) || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		return nil
	}
	return call.Arguments[index].Export()
}
