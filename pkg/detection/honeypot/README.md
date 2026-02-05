# Honeypot Detection Feature

## Overview

This feature adds automated honeypot detection capabilities to Nuclei, helping security researchers and penetration testers identify and avoid deceptive honeypot environments during vulnerability scanning.

## Feature Implementation

**Feature Issue**: #6403  
**Bounty**: $250  
**Branch**: `feature-honeypot-detection-6403`

## Architecture

The honeypot detection system consists of three main components:

### 1. Detection Engine (`pkg/detection/honeypot/honeypot.go`)

The core detection engine implements fingerprinting techniques to identify common honeypot systems:

- **Cowrie**: SSH/Telnet honeypot detection via banner analysis
- **Kippo**: Legacy SSH honeypot detection
- **Dionaea**: Malware collection honeypot detection
- **HoneyD**: Virtual honeypot detection
- **Glastopf**: Web application honeypot detection
- **Conpot**: ICS/SCADA honeypot detection
- **ElasticHoney**: Elasticsearch honeypot detection
- **Mailoney**: SMTP honeypot detection
- **SSHesame**: SSH honeypot detection

**Detection Methods:**

- SSH banner analysis (ports 22, 2222)
- Telnet banner patterns (port 23)
- HTTP/HTTPS response analysis (ports 80, 443, 8080, 8443)
- FTP banner detection (port 21)
- SMTP banner detection (port 25)
- Generic TCP banner keyword analysis

### 2. Target Filter (`pkg/detection/honeypot/filter.go`)

Provides a high-level interface for filtering targets based on honeypot detection:

- Caches detection results for performance
- Thread-safe concurrent access
- Integration with Nuclei's logging and colorization

### 3. Runner Integration (`internal/runner/runner.go`)

Integrates honeypot detection into Nuclei's main execution flow:

- Runs before template execution
- Configurable via CLI flags
- Optional warning-only or skip modes

## CLI Flags

### `--honeypot-detection` or `-hd`

Enables honeypot detection before scanning targets.

```bash
nuclei -u example.com -hd
```

### `--honeypot-skip` or `-hds`

When combined with `-hd`, this flag changes the behavior to skip detected honeypots entirely (default behavior is warn-only).

```bash
nuclei -u example.com -hd -hds
```

### `--honeypot-ports` or `-hdp`

Specify custom ports for honeypot detection (comma-separated).

```bash
nuclei -u example.com -hd -hdp 22,80,443,8080
```

### `--honeypot-threshold` or `-hdt`

Set the confidence threshold for honeypot detection (0-100 percent, default: 60%).

```bash
nuclei -u example.com -hd -hdt 75
```

## Usage Examples

### Basic Honeypot Detection

Scan a target with honeypot detection enabled:

```bash
nuclei -u example.com -hd
```

Output:

```log
[INF] Starting honeypot detection phase...
[WRN] Target is a suspected honeypot: example.com:22 [Type: cowrie, Confidence: 85%]
[INF] Honeypot detection completed: 1 targets flagged
```

### Skip Detected Honeypots

Automatically skip targets identified as honeypots:

```bash
nuclei -u example.com -hd -hds
```

### Custom Port Scanning

Check specific ports for honeypot indicators:

```bash
nuclei -l targets.txt -hd -hdp 22,2222,8022
```

### Adjust Confidence Threshold

Set a higher confidence threshold (75%):

```bash
nuclei -u example.com -hd -hdt 75
```

## Detection Signatures

### SSH Honeypots

**Cowrie**:

- `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2`
- `SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.4`
- `SSH-2.0-OpenSSH_6.0p1`

**Kippo**:

- `SSH-2.0-OpenSSH_5.1p1 Debian-5`
- `SSH-1.99-OpenSSH_4.7p1`

**SSHesame**:

- `SSH-2.0-sshesame`

**Generic SSH Indicators**:

- Very old OpenSSH versions (3.x, 4.x, 5.x)
- libssh-based servers
- Debian 7 (EOL) default SSH configurations
- SSH-1.99 compatibility mode

### Telnet Honeypots

**Cowrie Telnet**:

- `BusyBox v1.19.4`
- `BusyBox v1.20.2`
- `BusyBox built-in shell`
- `DD-WRT v24-sp2`

### HTTP/HTTPS Honeypots

**Glastopf**:

- Response contains "glastopf" keyword
- "Blog Comments" in response

**Generic HTTP Indicators**:

- Response contains "honeypot" or "honeytoken"
- Server header: "cowrie", "dionaea"

### FTP Honeypots

**Dionaea**:

- `220 DiskStation FTP server ready`
- `220 FTP server ready`

### SMTP Honeypots

**Mailoney**:

- `220 localhost ESMTP Postfix`
- `220 mailhoney`

## Implementation Details

### Confidence Scoring

Each detection method returns a confidence score (0.0 to 1.0):

- **0.95**: Explicit honeypot identification (e.g., SSHesame banner)
- **0.85**: Strong signature match (e.g., Cowrie default banner)
- **0.80**: Known honeypot pattern (e.g., Kippo banner)
- **0.70**: Suspicious but not definitive
- **0.50**: Weak indicator (old versions, generic patterns)

### Concurrent Scanning

The detector uses a worker pool pattern for efficient port scanning:

- Default concurrency: 5 workers
- Configurable via Options.Concurrency
- Timeout-based connection handling (default: 5 seconds)

### Caching

Detection results are cached in memory to avoid redundant checks:

- Thread-safe access via sync.RWMutex
- Results persist for the lifetime of the runner
- Cache can be cleared via `TargetFilter.Clear()`

## Testing

The package includes comprehensive unit tests:

```bash
cd pkg/detection/honeypot
go test -v
```

Test coverage includes:

- Detector initialization
- Target parsing
- SSH banner detection
- Generic banner analysis
- Target filter functionality
- Concurrency and thread safety

## Performance Considerations

- **Timeout**: Each port check has a 5-second timeout by default
- **Concurrency**: Max 5 concurrent port checks per target
- **Banner Reading**: Limited to first 4096 bytes
- **HTTP Detection**: Sends minimal GET request, reads up to 8192 bytes

## Limitations

1. **Network Access**: Requires outbound network access to target ports
2. **False Positives**: EOL systems may be flagged as honeypots
3. **Evolving Signatures**: Honeypot fingerprints may change over time
4. **Encrypted Protocols**: Limited detection for encrypted/authenticated services
5. **Custom Honeypots**: May not detect custom or novel honeypot implementations

## Future Enhancements

Potential improvements for future versions:

1. **Behavioral Analysis**: Detect honeypots based on response timing patterns
2. **Machine Learning**: Use ML models for advanced honeypot classification
3. **Community Signatures**: Crowd-sourced honeypot signature database
4. **Deep Inspection**: Analyze full protocol handshakes (not just banners)
5. **Reputation Integration**: Cross-reference with known honeypot IP databases

## Integration with Nuclei Workflow

The honeypot detection feature integrates seamlessly with Nuclei's existing workflow:

1. **Input Provider Setup**: Targets are loaded into the input provider
2. **Honeypot Detection Phase**: If `-hd` is enabled, all targets are checked
3. **Warning/Filtering**: Detected honeypots are either warned about or skipped
4. **Template Execution**: Nuclei proceeds with normal template execution
5. **Output**: Detection results are logged but don't appear in final results

## Code Quality

- **Static Analysis**: Passes `go vet` and `golint`
- **Test Coverage**: Comprehensive unit test suite
- **Documentation**: Inline code comments and package documentation
- **Error Handling**: Graceful handling of network errors and timeouts
- **Logging**: Structured logging via gologger

## Contributing

To add new honeypot signatures:

1. Identify unique fingerprints (banners, headers, responses)
2. Add detection logic to appropriate check method
3. Define new HoneypotType constant if needed
4. Add test cases to `honeypot_test.go`
5. Update this README with new signatures

## License

This feature follows Nuclei's existing license (MIT).

## Credits

- Feature implementation: Ali Akbar
- Research: Common honeypot fingerprints from security community
- Testing: Nuclei maintainers and community

## References

- Cowrie: <https://github.com/cowrie/cowrie>
- Kippo: <https://github.com/desaster/kippo>
- Dionaea: <https://github.com/DinoTools/dionaea>
- Glastopf: <https://github.com/mushorg/glastopf>
- Conpot: <https://github.com/mushorg/conpot>

---

**Note**: This feature enhances Nuclei's reconnaissance capabilities by helping users identify and avoid honeypot environments. It should be used responsibly and ethically as part of authorized security testing activities.
