// telnetmini.go
// Minimal Telnet helper for authentication + simple I/O over an existing or new connection.

package telnetmini

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Telnet protocol constants
const (
	IAC     = 255 // Interpret As Command
	WILL    = 251 // Will
	WONT    = 252 // Won't
	DO      = 253 // Do
	DONT    = 254 // Don't
	SB      = 250 // Subnegotiation Begin
	SE      = 240 // Subnegotiation End
	ENCRYPT = 38  // Encryption option (0x26)
)

// EncryptionInfo contains information about telnet encryption support
type EncryptionInfo struct {
	SupportsEncryption bool
	Banner             string
	Options            map[int][]int
}

// Client wraps a Telnet connection with tiny helpers.
type Client struct {
	Conn            net.Conn
	rd              *bufio.Reader
	wr              *bufio.Writer
	LoginPrompts    []string // matched case-insensitively
	UserPrompts     []string // alternative to LoginPrompts; if empty, LoginPrompts used for username step
	PasswordPrompts []string
	FailBanners     []string // e.g., "login incorrect", "authentication failed"
	ShellPrompts    []string // e.g., "$ ", "# ", "> "
	ReadCapBytes    int      // safety cap while scanning (default 64 KiB)
}

// Defaults sets reasonable prompt patterns if none provided.
func (c *Client) Defaults() {
	if c.ReadCapBytes == 0 {
		c.ReadCapBytes = 64 * 1024
	}
	if len(c.LoginPrompts) == 0 {
		c.LoginPrompts = []string{"login:", "username:"}
	}
	if len(c.PasswordPrompts) == 0 {
		c.PasswordPrompts = []string{"password:"}
	}
	if len(c.FailBanners) == 0 {
		c.FailBanners = []string{"login incorrect", "authentication failed", "login failed"}
	}
	if len(c.ShellPrompts) == 0 {
		c.ShellPrompts = []string{"$ ", "# ", "> "}
	}
	if len(c.UserPrompts) == 0 {
		c.UserPrompts = c.LoginPrompts
	}
}

// New wraps an existing net.Conn.
func New(conn net.Conn) *Client {
	c := &Client{
		Conn: conn,
		rd:   bufio.NewReader(conn),
		wr:   bufio.NewWriter(conn),
	}
	c.Defaults()
	return c
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.Conn.Close()
}

// DetectEncryption detects if a telnet server supports encryption.
// Based on Nmap's telnet-encryption.nse script functionality.
// WARNING: The connection becomes unusable after calling this function
// due to the encryption negotiation packets sent.
func DetectEncryption(conn net.Conn, timeout time.Duration) (*EncryptionInfo, error) {
	if timeout == 0 {
		timeout = 7 * time.Second
	}

	// Set connection timeout
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send encryption negotiation packet (based on Nmap script)
	// FF FD 26 FF FB 26 = IAC DO ENCRYPT IAC WILL ENCRYPT
	encryptionPacket := []byte{IAC, DO, ENCRYPT, IAC, WILL, ENCRYPT}
	_, err := conn.Write(encryptionPacket)
	if err != nil {
		return nil, fmt.Errorf("failed to send encryption packet: %w", err)
	}

	// Process server responses
	options := make(map[int][]int)
	supportsEncryption := false
	banner := ""

	// Read responses until we get encryption info or timeout
	for {
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			// Timeout or connection closed, break
			break
		}

		if n > 0 {
			data := buffer[:n]
			// Check if this contains banner text (non-IAC bytes)
			for _, b := range data {
				if b != IAC {
					banner += string(b)
				}
			}

			// Process telnet options
			encrypted, opts := processTelnetOptions(data)
			if encrypted {
				supportsEncryption = true
			}

			// Merge options
			for opt, cmds := range opts {
				if options[opt] == nil {
					options[opt] = make([]int, 0)
				}
				options[opt] = append(options[opt], cmds...)
			}

			// Check if we have encryption info
			if cmds, exists := options[ENCRYPT]; exists {
				for _, cmd := range cmds {
					if cmd == WILL || cmd == DO {
						supportsEncryption = true
						break
					}
				}
			}
		}
	}

	return &EncryptionInfo{
		SupportsEncryption: supportsEncryption,
		Banner:             banner,
		Options:            options,
	}, nil
}

// processTelnetOptions processes telnet protocol options and returns encryption support status
func processTelnetOptions(data []byte) (bool, map[int][]int) {
	options := make(map[int][]int)
	supportsEncryption := false

	for i := 0; i < len(data); i++ {
		if data[i] == IAC && i+2 < len(data) {
			cmd := data[i+1]
			option := data[i+2]

			// Initialize option slice if not exists
			optInt := int(option)
			if options[optInt] == nil {
				options[optInt] = make([]int, 0)
			}
			options[optInt] = append(options[optInt], int(cmd))

			// Check for encryption support
			if option == ENCRYPT && (cmd == WILL || cmd == DO) {
				supportsEncryption = true
			}

			// Handle subnegotiation
			if cmd == SB {
				// Skip until SE
				for j := i + 3; j < len(data); j++ {
					if data[j] == IAC && j+1 < len(data) && data[j+1] == SE {
						i = j + 1
						break
					}
				}
			} else {
				i += 2 // Skip command and option
			}
		}
	}

	return supportsEncryption, options
}

// Auth performs a minimal Telnet username/password interaction.
// It waits for a username/login prompt, sends username, waits for a password prompt,
// sends password, and then looks for fail banners or shell prompts.
// A timeout should be enforced via ctx.
func (c *Client) Auth(ctx context.Context, username, password string) error {
	// Wait for username/login prompt
	if _, _, err := c.readUntil(ctx, c.UserPrompts...); err != nil {
		return fmt.Errorf("waiting for login/username prompt: %w", err)
	}
	if err := c.writeLine(ctx, username); err != nil {
		return fmt.Errorf("sending username: %w", err)
	}

	// Wait for password prompt
	if _, _, err := c.readUntil(ctx, c.PasswordPrompts...); err != nil {
		return fmt.Errorf("waiting for password prompt: %w", err)
	}
	if err := c.writeLine(ctx, password); err != nil {
		return fmt.Errorf("sending password: %w", err)
	}

	// Post-auth: look quickly for explicit failure, else accept shell prompt / silence.
	match, got, err := c.readUntil(ctx,
		append(append([]string{}, c.FailBanners...), c.ShellPrompts...)...,
	)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("post-auth read: %s (got: %s)", preview(got, 200), err)
	}
	low := strings.ToLower(match)
	for _, fb := range c.FailBanners {
		if low == strings.ToLower(fb) {
			return errors.New("authentication failed")
		}
	}
	// success (matched a shell prompt or timed out without explicit failure)
	return nil
}

// Exec sends a command followed by CRLF and returns text captured until one of
// the provided prompts appears (typically your shell prompt). Provide a deadline via ctx.
func (c *Client) Exec(ctx context.Context, command string, until ...string) (string, error) {
	if err := c.writeLine(ctx, command); err != nil {
		return "", err
	}
	_, out, err := c.readUntil(ctx, until...)
	return out, err
}

// --- internals ---

// writeLine writes s + CRLF and flushes.
func (c *Client) writeLine(ctx context.Context, s string) error {
	c.setDeadlineFromCtx(ctx, true)
	if _, err := io.WriteString(c.wr, s+"\r\n"); err != nil {
		return err
	}
	return c.wr.Flush()
}

// readUntil scans bytes, handles minimal Telnet IAC negotiation, and returns when any needle appears.
func (c *Client) readUntil(ctx context.Context, needles ...string) (matched string, bufStr string, err error) {
	if len(needles) == 0 {
		return "", "", errors.New("readUntil: no needles provided")
	}
	c.setDeadlineFromCtx(ctx, false)

	lowNeedles := make([]string, len(needles))
	for i, n := range needles {
		lowNeedles[i] = strings.ToLower(n)
	}

	var b strings.Builder
	tmp := make([]byte, 1)

	// Maximum iteration counter to prevent infinite loops
	maxIterations := 20
	iterationCount := 0

	for {
		iterationCount++
		// if we have iterated more than maxIterations, return
		if iterationCount > maxIterations {
			return "", b.String(), nil
		}
		// honor context deadline on every read
		c.setDeadlineFromCtx(ctx, false)
		_, err := c.rd.Read(tmp)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return "", b.String(), context.DeadlineExceeded
			}
			return "", b.String(), err
		}

		// Telnet IAC (Interpret As Command)
		if tmp[0] == 255 { // IAC
			cmd, err := c.rd.ReadByte()
			if err != nil {
				return "", b.String(), err
			}
			switch cmd {
			case 251, 252, 253, 254: // WILL, WONT, DO, DONT
				opt, err := c.rd.ReadByte()
				if err != nil {
					return "", b.String(), err
				}
				// Politely refuse everything: DONT to WILL; WONT to DO.
				var reply []byte
				if cmd == 251 { // WILL
					reply = []byte{255, 254, opt} // DONT
				}
				if cmd == 253 { // DO
					reply = []byte{255, 252, opt} // WONT
				}
				if len(reply) > 0 {
					c.setDeadlineFromCtx(ctx, true)
					_, _ = c.wr.Write(reply)
					_ = c.wr.Flush()
				}
			case 250: // SB (subnegotiation): skip until SE
				for {
					bb, err := c.rd.ReadByte()
					if err != nil {
						return "", b.String(), err
					}
					if bb == 255 {
						if se, err := c.rd.ReadByte(); err == nil && se == 240 { // SE
							break
						}
					}
				}
			default:
				// NOP for other commands (IAC NOP, GA, etc.)
			}
			continue
		}

		// regular data byte
		b.WriteByte(tmp[0])
		lower := strings.ToLower(b.String())
		for i, n := range lowNeedles {
			if strings.Contains(lower, n) {
				return needles[i], b.String(), nil
			}
		}
		if b.Len() > c.ReadCapBytes {
			return "", b.String(), errors.New("prompt not found (read cap reached)")
		}
	}
}

func (c *Client) setDeadlineFromCtx(ctx context.Context, write bool) {
	if ctx == nil {
		return
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.Conn.SetReadDeadline(dl)
		if write {
			_ = c.Conn.SetWriteDeadline(dl)
		}
	}
}

func preview(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
