package wmi

import (
	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
)

// Auth exposes WMI authentication constructors.
var Auth = goexec.AuthConstructors()

// Client is a GoExec-backed WMI execution client.
type Client struct {
	target  string
	auth    *goexec.Auth
	options goexec.ExecutionOptions
	nj      *utils.NucleiJS
}

// NewClient constructs a WMI client.
//
// Constructor: constructor(target: string, auth: any)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	nj := utils.NewNucleiJS(runtime)
	nj.ObjectSig = "Client(target, auth)"
	client := &Client{
		options: goexec.DefaultExecutionOptions(),
		nj:      nj,
	}
	client.target, _ = nj.GetArg(call.Arguments, 0).(string)
	if auth, ok := nj.GetArg(call.Arguments, 1).(*goexec.Auth); ok {
		client.auth = auth
	} else {
		nj.Throw("auth must be created with wmi.Auth")
	}
	obj := runtime.NewObject()
	client.bindAliases(obj, runtime)
	return obj
}

// SetOptions updates default execution options for future client calls.
func (c *Client) SetOptions(opts interface{}) {
	c.options = goexec.MergeOptions(c.options, opts)
}

// Command runs a Windows command line through WMI Win32_Process.Create.
func (c *Client) Command(command string, opts interface{}) map[string]interface{} {
	return c.run("command", goexec.Request{Command: command}, opts)
}

// Proc runs an executable and argument string through WMI Win32_Process.Create.
func (c *Client) Proc(executable string, args string, opts interface{}) map[string]interface{} {
	return c.run("proc", goexec.Request{Executable: executable, Args: args}, opts)
}

// Call invokes a WMI class method and returns the serialized method response.
func (c *Client) Call(namespace string, className string, method string, argsJSON string, opts interface{}) map[string]interface{} {
	return c.run("call", goexec.Request{
		Namespace:      namespace,
		ClassName:      className,
		MethodName:     method,
		MethodArgsJSON: argsJSON,
	}, opts)
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
	_ = obj.Set("command", func(call goja.FunctionCall) goja.Value {
		command, _ := exportArg(call, 0).(string)
		return runtime.ToValue(c.Command(command, exportArg(call, 1)))
	})
	_ = obj.Set("Command", func(call goja.FunctionCall) goja.Value {
		command, _ := exportArg(call, 0).(string)
		return runtime.ToValue(c.Command(command, exportArg(call, 1)))
	})
	_ = obj.Set("proc", func(call goja.FunctionCall) goja.Value {
		executable, _ := exportArg(call, 0).(string)
		args, _ := exportArg(call, 1).(string)
		return runtime.ToValue(c.Proc(executable, args, exportArg(call, 2)))
	})
	_ = obj.Set("Proc", func(call goja.FunctionCall) goja.Value {
		executable, _ := exportArg(call, 0).(string)
		args, _ := exportArg(call, 1).(string)
		return runtime.ToValue(c.Proc(executable, args, exportArg(call, 2)))
	})
	_ = obj.Set("call", func(call goja.FunctionCall) goja.Value {
		namespace, _ := exportArg(call, 0).(string)
		className, _ := exportArg(call, 1).(string)
		method, _ := exportArg(call, 2).(string)
		argsJSON, _ := exportArg(call, 3).(string)
		return runtime.ToValue(c.Call(namespace, className, method, argsJSON, exportArg(call, 4)))
	})
	_ = obj.Set("Call", func(call goja.FunctionCall) goja.Value {
		namespace, _ := exportArg(call, 0).(string)
		className, _ := exportArg(call, 1).(string)
		method, _ := exportArg(call, 2).(string)
		argsJSON, _ := exportArg(call, 3).(string)
		return runtime.ToValue(c.Call(namespace, className, method, argsJSON, exportArg(call, 4)))
	})
}

func (c *Client) run(method string, partial goexec.Request, opts interface{}) map[string]interface{} {
	options := goexec.MergeOptions(c.options, opts)
	req := partial
	req.Module = "wmi"
	req.Method = method
	req.Target = c.target
	req.Auth = c.auth
	req.Options = options
	return goexec.Run(goexec.WithExecutionID(c.nj.Context(), c.nj.ExecutionId()), req).Public()
}

func exportArg(call goja.FunctionCall, index int) interface{} {
	if index >= len(call.Arguments) || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		return nil
	}
	return call.Arguments[index].Export()
}
