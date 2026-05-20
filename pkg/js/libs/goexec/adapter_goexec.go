package goexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	upstream "github.com/FalconOpsLLC/goexec/pkg/goexec"
	godce "github.com/FalconOpsLLC/goexec/pkg/goexec/dce"
	godcom "github.com/FalconOpsLLC/goexec/pkg/goexec/dcom"
	goscmr "github.com/FalconOpsLLC/goexec/pkg/goexec/scmr"
	gosmb "github.com/FalconOpsLLC/goexec/pkg/goexec/smb"
	gotsch "github.com/FalconOpsLLC/goexec/pkg/goexec/tsch"
	gowmi "github.com/FalconOpsLLC/goexec/pkg/goexec/wmi"
	"github.com/RedTeamPentesting/adauth"
	"github.com/google/uuid"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/rs/zerolog"
)

// GoExecRunner maps nuclei helper requests to FalconOps GoExec library calls.
type GoExecRunner struct{}

func (r *GoExecRunner) Run(ctx context.Context, req Request) (*Result, error) {
	result := newResult(req)
	redactor := newRedactor(req.Auth)

	if err := req.Auth.validate(); err != nil {
		return result, err
	}
	if !protocolstate.IsHostAllowed(executionID(ctx), targetHost(req.Target)) {
		return result, protocolstate.ErrHostDenied.Msgf(req.Target)
	}
	if req.Auth.domainController != "" && !protocolstate.IsHostAllowed(executionID(ctx), targetHost(req.Auth.domainController)) {
		return result, ErrDomainControllerDenied
	}
	if req.Options.Proxy != "" && !proxyAllowed(ctx, req.Options.Proxy) {
		return result, ErrProxyDenied
	}
	if req.Options.Endpoint != "" && !endpointAllowed(ctx, req.Options.Endpoint) {
		return result, ErrEndpointDenied
	}
	if req.Options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.Options.Timeout)*time.Second)
		defer cancel()
	}
	ctx = gssapi.NewSecurityContext(ctx)
	ctx = zerolog.New(io.Discard).WithContext(ctx)

	var err error
	switch strings.ToLower(req.Module) {
	case "wmi":
		err = r.runWMI(ctx, req, result)
	case "tsch":
		err = r.runTSCH(ctx, req, result)
	case "scmr":
		err = r.runSCMR(ctx, req, result)
	case "dcom":
		err = r.runDCOM(ctx, req, result)
	default:
		err = ErrUnsupportedModule
	}
	if err != nil {
		result.Error = redactor.Error(err)
		result.OK = false
		return result, nil
	}
	result.OK = true
	result.ExitCode = 0
	return result, nil
}

func (r *GoExecRunner) runWMI(ctx context.Context, req Request, result *Result) error {
	switch strings.ToLower(req.Method) {
	case "command", "proc":
		execIO, err := r.executionIO(ctx, req, result)
		if err != nil {
			return err
		}
		client, err := r.dceClient(ctx, req, "cifs", "")
		if err != nil {
			return err
		}
		module := &gowmi.WmiProc{
			Wmi: gowmi.Wmi{
				Client:   client,
				Resource: "//./root/cimv2",
			},
			WorkingDirectory: req.Options.Directory,
		}
		if err := upstream.ExecuteCleanMethod(ctx, module, execIO); err != nil {
			return err
		}
		collectExecutionOutput(req, result, execIO)
		return nil
	case "call":
		client, err := r.dceClient(ctx, req, "cifs", "")
		if err != nil {
			return err
		}
		args := map[string]any{}
		if req.MethodArgsJSON != "" {
			if err := json.Unmarshal([]byte(req.MethodArgsJSON), &args); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalidMethodArguments, err)
			}
		}
		var out bytes.Buffer
		module := &gowmi.WmiCall{
			Wmi: gowmi.Wmi{
				Client:   client,
				Resource: defaultString(req.Namespace, "//./root/cimv2"),
			},
			Class:  req.ClassName,
			Method: req.MethodName,
			Args:   args,
			Out:    &out,
		}
		if module.Class == "" || module.Method == "" {
			return ErrInvalidMethodArguments
		}
		if err := upstream.ExecuteCleanAuxiliaryMethod(ctx, module); err != nil {
			return err
		}
		result.Stdout = out.String()
		result.OutputCollected = true
		return nil
	default:
		return ErrUnsupportedMethod
	}
}

func (r *GoExecRunner) runTSCH(ctx context.Context, req Request, result *Result) error {
	execIO, err := r.executionIO(ctx, req, result)
	if err != nil {
		return err
	}
	client, err := r.dceClient(ctx, req, "cifs", "ncacn_np:[atsvc]")
	if err != nil {
		return err
	}
	switch strings.ToLower(req.Method) {
	case "demand":
		module := &gotsch.TschDemand{
			Tsch: gotsch.Tsch{
				Client:   client,
				TaskPath: taskPath(req.TaskName),
			},
		}
		result.Cleanup.Attempted = true
		if err := upstream.ExecuteCleanMethod(ctx, module, execIO); err != nil {
			return err
		}
		collectExecutionOutput(req, result, execIO)
		return nil
	case "create":
		module := &gotsch.TschCreate{
			Tsch: gotsch.Tsch{
				Client:   client,
				TaskPath: taskPath(req.TaskName),
			},
			CallDelete: true,
		}
		result.Cleanup.Attempted = true
		if err := upstream.ExecuteCleanMethod(ctx, module, execIO); err != nil {
			return err
		}
		collectExecutionOutput(req, result, execIO)
		return nil
	default:
		return ErrUnsupportedMethod
	}
}

func (r *GoExecRunner) runSCMR(ctx context.Context, req Request, result *Result) error {
	execIO, err := r.executionIO(ctx, req, result)
	if err != nil {
		return err
	}
	client, err := r.dceClient(ctx, req, "cifs", "ncacn_np:[svcctl]")
	if err != nil {
		return err
	}
	module := &goscmr.ScmrCreate{
		Scmr: goscmr.Scmr{
			Client: client,
		},
		ServiceName: req.ServiceName,
	}
	result.Cleanup.Attempted = true
	if err := upstream.ExecuteCleanMethod(ctx, module, execIO); err != nil {
		return err
	}
	collectExecutionOutput(req, result, execIO)
	return nil
}

func (r *GoExecRunner) runDCOM(ctx context.Context, req Request, result *Result) error {
	if strings.ToLower(req.Method) != "mmc" {
		return ErrUnsupportedMethod
	}
	execIO, err := r.executionIO(ctx, req, result)
	if err != nil {
		return err
	}
	client, err := r.dceClient(ctx, req, "cifs", "")
	if err != nil {
		return err
	}
	module := &godcom.DcomMmc{
		Dispatch: godcom.Dispatch{
			Dcom: godcom.Dcom{
				Client: client,
			},
		},
		WorkingDirectory: req.Options.Directory,
		WindowState:      "Minimized",
	}
	if err := upstream.ExecuteCleanMethod(ctx, module, execIO); err != nil {
		return err
	}
	collectExecutionOutput(req, result, execIO)
	return nil
}

func (r *GoExecRunner) dceClient(ctx context.Context, req Request, protocol, endpoint string) (*godce.Client, error) {
	credential, target, err := r.credentials(ctx, protocol, req)
	if err != nil {
		return nil, err
	}
	client := &godce.Client{}
	client.Credential = credential
	client.Target = target
	client.Proxy = req.Options.Proxy
	client.NoSign = req.Options.NoSign
	client.NoSeal = req.Options.NoSeal
	client.Endpoint = req.Options.Endpoint
	client.Filter = req.Options.EPMFilter
	if client.Endpoint == "" && endpoint != "" {
		client.Endpoint = endpoint
	}
	if client.Endpoint == "" {
		client.UseEpm = true
	}
	if req.Options.EPM {
		client.UseEpm = true
	}
	if err := client.Parse(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

func (r *GoExecRunner) smbClient(ctx context.Context, req Request) (*gosmb.Client, error) {
	credential, target, err := r.credentials(ctx, "cifs", req)
	if err != nil {
		return nil, err
	}
	client := &gosmb.Client{}
	client.Credential = credential
	client.Target = target
	client.Proxy = req.Options.Proxy
	client.NoSign = req.Options.NoSign
	client.NoSeal = req.Options.NoSeal
	if err := client.Parse(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

func (r *GoExecRunner) credentials(ctx context.Context, protocol string, req Request) (*adauth.Credential, *adauth.Target, error) {
	opts := &adauth.Options{
		User:             req.Auth.username,
		Password:         req.Auth.password,
		NTHash:           req.Auth.ntHash,
		AESKey:           req.Auth.aesKey,
		CCache:           req.Auth.ccache,
		DomainController: req.Auth.domainController,
		ForceKerberos:    req.Auth.kerberos,
		PFXFileName:      req.Auth.pfxPath,
		PFXPassword:      req.Auth.pfxPassword,
	}
	return opts.WithTarget(ctx, protocol, req.Target)
}

func (r *GoExecRunner) executionIO(ctx context.Context, req Request, result *Result) (*upstream.ExecutionIO, error) {
	input := &upstream.ExecutionInput{
		Executable: req.Executable,
		Arguments:  req.Args,
		Command:    req.Command,
	}
	if req.Method == "command" && req.Command == "" {
		return nil, ErrMissingCommand
	}
	if req.Method != "command" && req.Executable == "" && req.Command == "" {
		return nil, ErrMissingExecutable
	}
	execIO := &upstream.ExecutionIO{
		Input: input,
	}
	if !req.Options.Output {
		return execIO, nil
	}
	if req.Options.OutputMethod != "" && req.Options.OutputMethod != DefaultOutputMethod {
		return nil, ErrUnsupportedOutputMethod
	}

	var out bytes.Buffer
	output := &upstream.ExecutionOutput{
		NoDelete:   req.Options.NoDeleteOutput,
		RemotePath: `C:\Windows\Temp\` + uuid.NewString(),
		Timeout:    time.Duration(req.Options.OutputTimeout) * time.Second,
		Writer:     nopWriteCloser{Writer: &out},
	}
	smbClient, err := r.smbClient(ctx, req)
	if err != nil {
		return nil, err
	}
	output.Provider = &gosmb.OutputFileFetcher{
		Client:           smbClient,
		Share:            `ADMIN$`,
		SharePath:        `C:\Windows`,
		File:             output.RemotePath,
		DeleteOutputFile: !output.NoDelete,
	}
	execIO.Output = output
	result.OutputMethod = DefaultOutputMethod
	result.Cleanup.Attempted = true
	result.Cleanup.Artifacts = []string{output.RemotePath}
	return execIO, nil
}

func collectExecutionOutput(req Request, result *Result, execIO *upstream.ExecutionIO) {
	if !req.Options.Output {
		return
	}
	result.Stdout = execIOOutput(execIO)
	result.OutputCollected = true
}

func execIOOutput(execIO *upstream.ExecutionIO) string {
	if execIO == nil || execIO.Output == nil || execIO.Output.Writer == nil {
		return ""
	}
	if writer, ok := execIO.Output.Writer.(interface{ String() string }); ok {
		return writer.String()
	}
	return ""
}

type nopWriteCloser struct {
	io.Writer
}

func (n nopWriteCloser) Close() error { return nil }

func (n nopWriteCloser) String() string {
	if s, ok := n.Writer.(interface{ String() string }); ok {
		return s.String()
	}
	return ""
}

func executionID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if value, ok := ctx.Value(executionIDKey).(string); ok && value != "" {
		return value
	}
	if value, ok := ctx.Value("executionId").(string); ok && value != "" {
		return value
	}
	if execCtx := protocolstate.GetExecutionContext(ctx); execCtx != nil {
		return execCtx.ExecutionID
	}
	return ""
}

func proxyAllowed(ctx context.Context, proxyURI string) bool {
	parsed, err := url.Parse(proxyURI)
	if err != nil || parsed.Hostname() == "" {
		return true
	}
	return protocolstate.IsHostAllowed(executionID(ctx), parsed.Hostname())
}

func endpointAllowed(ctx context.Context, endpoint string) bool {
	binding, err := dcerpc.ParseStringBinding(endpoint)
	if err != nil || binding.NetworkAddress == "" || binding.NetworkAddress == "0.0.0.0" || strings.HasPrefix(binding.NetworkAddress, "\\") {
		return true
	}
	return protocolstate.IsHostAllowed(executionID(ctx), binding.NetworkAddress)
}

func taskPath(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return `\` + uuid.NewString()
	}
	if strings.HasPrefix(name, `\`) {
		return name
	}
	return `\` + name
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
