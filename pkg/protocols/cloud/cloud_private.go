package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	tfjson "github.com/hashicorp/terraform-json"
	"github.com/magodo/terraform-client-go/tfclient"
	"github.com/magodo/terraform-client-go/tfclient/configschema"
	"github.com/magodo/terraform-client-go/tfclient/typ"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// experimental implementation for terraform provider client
// credits: @magodo for https://github.com/magodo/terraform-client-go.git

type TFProviderClient struct {
	logger hclog.Logger
	client tfclient.Client
	schema *typ.GetProviderSchemaResponse
}

func NewTFProviderClient(pluginPath string) (*TFProviderClient, error) {
	client := &TFProviderClient{}
	logger := &hclog.LoggerOptions{
		Output: hclog.DefaultOutput,
		Level:  hclog.LevelFromString(hclog.Error.String()),
		Name:   filepath.Base(pluginPath),
	}
	client.logger = hclog.New(logger)

	opts := tfclient.Option{
		Cmd:    exec.Command(pluginPath),
		Logger: client.logger,
	}

	reattach, err := parseReattach(os.Getenv("TF_REATTACH_PROVIDERS"))
	if err != nil {
		return nil, err
	}
	if reattach != nil {
		opts.Cmd = nil
		opts.Reattach = reattach
	}

	c, err := tfclient.New(opts)
	if err != nil {
		return nil, err
	}
	client.client = c

	// get schema of provider
	schema, diag := c.GetProviderSchema()
	if err := extractError(client.logger, diag); err != nil {
		return nil, err
	}
	client.schema = schema
	return client, nil
}

func (c *TFProviderClient) ConfigureProvider(ctx context.Context, config map[string]interface{}) error {
	blockType := configschema.SchemaBlockImpliedType(c.schema.Provider.Block)
	bin, _ := json.Marshal(config)
	value, err := ctyjson.Unmarshal(bin, blockType)
	if err != nil {
		return err
	}

	_, diag := c.client.ConfigureProvider(ctx, typ.ConfigureProviderRequest{
		Config: value,
	})
	return extractError(c.logger, diag)
}

func (c *TFProviderClient) GetDataSourceType(ctx context.Context, name string) cty.Type {
	return configschema.SchemaBlockImpliedType(c.schema.DataSources[name].Block)
}

func (c *TFProviderClient) GetSchema(name string) *tfjson.SchemaBlock {
	return c.schema.DataSources[name].Block
}

func (c *TFProviderClient) GetProviderMeta(ctx context.Context) (cty.Value, error) {
	provValue, err := ctyjson.Unmarshal([]byte(`{}`), configschema.SchemaBlockImpliedType(c.schema.ProviderMeta.Block))
	if err != nil {
		return cty.NilVal, err
	}
	return provValue, nil
}

func (c *TFProviderClient) GetTypedAttributes(ctx context.Context, name string, config map[string]interface{}) (cty.Value, error) {
	blockType := configschema.SchemaBlockImpliedType(c.schema.DataSources[name].Block)
	bin, _ := json.Marshal(config)
	value, err := ctyjson.Unmarshal(bin, blockType)
	if err != nil {
		return cty.NilVal, err
	}
	return value, nil
}

func (c *TFProviderClient) Do(ctx context.Context, name string, config cty.Value) (*typ.ReadDataSourceResponse, error) {
	prov_meta, err := c.GetProviderMeta(ctx)
	if err != nil {
		return nil, err
	}
	resp, diag := c.client.ReadDataSource(ctx, typ.ReadDataSourceRequest{
		TypeName:     name,
		Config:       config,
		ProviderMeta: prov_meta,
	})
	if err := extractError(c.logger, diag); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *TFProviderClient) ParseResponse(resp *typ.ReadDataSourceResponse, source string) ([]byte, error) {
	bin, err := ctyjson.Marshal(resp.State, configschema.SchemaBlockImpliedType(c.schema.DataSources[source].Block))
	if err != nil {
		// this is most likely a error we stored if it is string
		if resp.State.Type() == cty.String {
			return []byte(resp.State.AsString()), nil
		}
		return nil, err
	}
	return bin, nil
}

func parseReattach(in string) (*plugin.ReattachConfig, error) {
	if in == "" {
		return nil, nil
	}

	type reattachConfig struct {
		Protocol        string
		ProtocolVersion int
		Addr            struct {
			Network string
			String  string
		}
		Pid  int
		Test bool
	}
	var m map[string]reattachConfig
	err := json.Unmarshal([]byte(in), &m)
	if err != nil {
		return nil, fmt.Errorf("Invalid format for TF_REATTACH_PROVIDERS: %w", err)
	}
	if len(m) != 1 {
		return nil, fmt.Errorf("expect only one of provider specified in the TF_REATTACH_PROVIDERS, got=%d", len(m))
	}

	var c reattachConfig
	var p string
	for k, v := range m {
		c = v
		p = k
	}

	var addr net.Addr
	switch c.Addr.Network {
	case "unix":
		addr, err = net.ResolveUnixAddr("unix", c.Addr.String)
		if err != nil {
			return nil, fmt.Errorf("Invalid unix socket path %q: %w", c.Addr.String, err)
		}
	case "tcp":
		addr, err = net.ResolveTCPAddr("tcp", c.Addr.String)
		if err != nil {
			return nil, fmt.Errorf("Invalid TCP address %q: %w", c.Addr.String, err)
		}
	default:
		return nil, fmt.Errorf("Unknown address type %q for %q", c.Addr.Network, p)
	}
	return &plugin.ReattachConfig{
		Protocol:        plugin.Protocol(c.Protocol),
		ProtocolVersion: c.ProtocolVersion,
		Pid:             c.Pid,
		Test:            c.Test,
		Addr:            addr,
	}, nil
}

func extractError(logger hclog.Logger, diags typ.Diagnostics) error {
	for _, diag := range diags {
		if diag.Severity == typ.Error {
			return fmt.Errorf("%s: %s", diag.Summary, diag.Detail)
		}
	}
	if len(diags) != 0 {
		logger.Warn(diags.Err().Error())
	}
	return nil
}
