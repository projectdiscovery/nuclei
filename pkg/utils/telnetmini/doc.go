// Package telnetmini is a library for interacting with Telnet servers.
// it supports
//   - Basic Authentication phase (username/password)
//   - Encryption detection via encryption negotiation packet
//   - Minimal porting of https://github.com/nmap/nmap/blob/master/nselib/smbauth.lua SMB via NTLM negotiations
//     (TNAP Login Packet + Raw NTLM response parsing)
package telnetmini
