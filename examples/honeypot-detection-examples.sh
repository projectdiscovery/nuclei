#!/bin/bash

# Honeypot Detection Feature - Usage Examples
# This script demonstrates various ways to use the honeypot detection feature

echo "========================================="
echo "Nuclei Honeypot Detection - Examples"
echo "========================================="
echo ""

# Example 1: Basic honeypot detection
echo "Example 1: Basic Detection"
echo "Command: ./nuclei -u scanme.sh -hd"
echo "Description: Enable honeypot detection for a single target"
echo ""

# Example 2: Honeypot detection with skip mode
echo "Example 2: Detection with Skip Mode"
echo "Command: ./nuclei -u scanme.sh -hd -hds"
echo "Description: Detect and skip honeypots automatically"
echo ""

# Example 3: Custom ports
echo "Example 3: Custom Port Scanning"
echo "Command: ./nuclei -u scanme.sh -hd -hdp 22,2222,8022,80,443"
echo "Description: Check specific ports for honeypot indicators"
echo ""

# Example 4: High confidence threshold
echo "Example 4: High Confidence Threshold"
echo "Command: ./nuclei -u scanme.sh -hd -hdt 80"
echo "Description: Only flag targets with 80%+ confidence"
echo ""

# Example 5: Batch scanning
echo "Example 5: Batch Scanning with Detection"
echo "Command: ./nuclei -l targets.txt -hd -t templates/cves/"
echo "Description: Scan multiple targets with honeypot detection"
echo ""

# Example 6: Full featured
echo "Example 6: Full Featured Configuration"
echo "Command: ./nuclei -l targets.txt -hd -hds -hdp 22,80,443 -hdt 70 -t templates/"
echo "Description: Complete honeypot detection with custom settings"
echo ""

echo "========================================="
echo "Detection Capabilities"
echo "========================================="
echo ""
echo "Supported Honeypot Types:"
echo "  - Cowrie (SSH/Telnet)"
echo "  - Kippo (SSH)"
echo "  - Dionaea (Multi-protocol)"
echo "  - HoneyD (Virtual)"
echo "  - Glastopf (Web)"
echo "  - Conpot (ICS/SCADA)"
echo "  - ElasticHoney (Elasticsearch)"
echo "  - Mailoney (SMTP)"
echo "  - SSHesame (SSH)"
echo "  - Generic (keyword-based)"
echo ""
echo "Detection Methods:"
echo "  - SSH banner analysis (ports 22, 2222)"
echo "  - Telnet fingerprinting (port 23)"
echo "  - HTTP/HTTPS inspection (ports 80, 443, 8080, 8443)"
echo "  - FTP banner detection (port 21)"
echo "  - SMTP banner detection (port 25)"
echo "  - Generic TCP banner analysis"
echo ""
echo "========================================="
echo "Default Configuration"
echo "========================================="
echo ""
echo "Default Ports: 22, 23, 80, 443, 2222, 8080, 8443, 21, 25, 445, 3306, 5900"
echo "Default Threshold: 60%"
echo "Default Mode: Warn only (does not skip)"
echo "Default Timeout: 5 seconds per port"
echo "Default Concurrency: 5 workers"
echo ""
echo "========================================="
echo "For more information, see:"
echo "  - pkg/detection/honeypot/README.md"
echo "  - IMPLEMENTATION_SUMMARY.md"
echo "========================================="
