![nuclei](/static/nuclei-cover-image.png)

<div align="center">
  
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">`English`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md">`中文`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_KR.md">`Korean`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ID.md">`Indonesia`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ES.md">`Spanish`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_JP.md">`日本語`</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_PT-BR.md">`Portuguese`</a>
  
</div>

<p align="center">

<img src="https://img.shields.io/badge/go-1.22-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white">
&nbsp;&nbsp;
<a href="https://docs.projectdiscovery.io/tools/nuclei/overview?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme"><img src="https://img.shields.io/badge/Documentation-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBjbGFzcz0ibHVjaWRlIGx1Y2lkZS1ib29rLW9wZW4iPjxwYXRoIGQ9Ik0xMiA3djE0Ii8+PHBhdGggZD0iTTMgMThhMSAxIDAgMCAxLTEtMVY0YTEgMSAwIDAgMSAxLTFoNWE0IDQgMCAwIDEgNCA0IDQgNCAwIDAgMSA0LTRoNWExIDEgMCAwIDEgMSAxdjEzYTEgMSAwIDAgMS0xIDFoLTZhMyAzIDAgMCAwLTMgMyAzIDMgMCAwIDAtMy0zeiIvPjwvc3ZnPg==&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://github.com/projectdiscovery/nuclei-templates"><img src="https://img.shields.io/badge/Templates Library-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMS41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGNsYXNzPSJsdWNpZGUgbHVjaWRlLXNoaWVsZCI+PHBhdGggZD0iTTIwIDEzYzAgNS0zLjUgNy41LTcuNjYgOC45NWExIDEgMCAwIDEtLjY3LS4wMUM3LjUgMjAuNSA0IDE4IDQgMTNWNmExIDEgMCAwIDEgMS0xYzIgMCA0LjUtMS4yIDYuMjQtMi43MmExLjE3IDEuMTcgMCAwIDEgMS41MiAwQzE0LjUxIDMuODEgMTcgNSAxOSA1YTEgMSAwIDAgMSAxIDF6Ii8+PC9zdmc+&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://discord.gg/projectdiscovery?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme"><img src="https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white"></a>

<hr>

</p>

<br>

**Nuclei is a modern, high-performance vulnerability scanner that leverages simple YAML-based templates. It empowers you to design custom vulnerability detection scenarios that mimic real-world conditions, leading to zero false positives.**

- Simple YAML format for creating and customizing vulnerability templates.
- Contributed by thousands of security professionals to tackle trending vulnerabilities.
- Reduce false positives by simulating real-world steps to verify a vulnerability.
- Ultra-fast parallel scan processing and request clustering.
- Integrate into CI/CD pipelines for vulnerability detection and regression testing.
- Supports multiple protocols like TCP, DNS, HTTP, SSL, WHOIS JavaScript, Code and more.
- Integrate with Jira, Splunk, GitHub, Elastic, GitLab.

<br>
<br>

## Table of Contents

- [**`Get Started`**](#get-started)
  - [_`1. Nuclei CLI`_](#1-nuclei-cli)
  - [_`2. Pro and Enterprise Editions`_](#2-pro-and-enterprise-editions)
- [**`Documentation`**](#documentation)
  - [_`Command Line Flags`_](#command-line-flags)
  - [_`Single target scan`_](#single-target-scan)
  - [_`Scanning multiple targets`_](#scanning-multiple-targets)
  - [_`Network scan`_](#network-scan)
  - [_`Scanning with your custom template`_](#scanning-with-your-custom-template)
  - [_`Connect Nuclei to ProjectDiscovery_`_](#connect-nuclei-to-projectdiscovery)
- [**`Nuclei Templates, Community and Rewards`**](#nuclei-templates-community-and-rewards-) 💎
- [**`Our Mission`**](#our-mission)
- [**`Contributors`**](#contributors-heart) ❤
- [**`License`**](#license)

<br>
<br>

## Get Started

### **1. Nuclei CLI**

_Install Nuclei on your machine. Get started by following the installation guide [**`here`**](https://docs.projectdiscovery.io/tools/nuclei/install?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme). Additionally, We provide [**`a free cloud tier`**](https://cloud.projectdiscovery.io/sign-up) and comes with a generous monthly free limits:_

- Store and visualize your vulnerability findings
- Write and manage your nuclei templates
- Access latest nuclei templates
- Discover and store your targets

> [!Important]
> |**This project is in active development**. Expect breaking changes with releases. Review the release changelog before updating.|
> |:--------------------------------|
> | This project is primarily built to be used as a standalone CLI tool. **Running nuclei as a service may pose security risks.** It's recommended to use with caution and additional security measures. |

<br>

### **2. Pro and Enterprise Editions**

_For security teams and enterprises, we provide a cloud-hosted service built on top of Nuclei OSS, fine-tuned to help you continuously run vulnerability scans at scale with your team and existing workflows:_

- 50x faster scans
- Large scale scanning with high accuracy
- Integrations with cloud services (AWS, GCP, Azure, CloudFlare, Fastly, Terraform, Kubernetes)
- Jira, Slack, Linear, APIs and Webhooks
- Executive and compliance reporting
- Plus: Real-time scanning, SAML SSO, SOC 2 compliant platform (with EU and US hosting options), shared team workspaces, and more
- We're constantly [**`adding new features`**](https://feedback.projectdiscovery.io/changelog)!
- **Ideal for:** Pentesters, security teams, and enterprises

[**`Sign up to Pro`**](https://projectdiscovery.io/pricing?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme) or [**`Talk to our team`**](https://projectdiscovery.io/request-demo?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme) if you have large organization and complex requirements.

<br>
<br>

## Documentation

Browse the full Nuclei [**`documentation here`**](https://docs.projectdiscovery.io/tools/nuclei/running). If you’re new to Nuclei, check out our [**`foundational Youtube series`**](https://www.youtube.com/playlist?list=PLZRbR9aMzTTpItEdeNSulo8bYsvil80Rl).

<div align="center">

<a href="https://www.youtube.com/watch?v=b5qMyQvL1ZA&list=PLZRbR9aMzTTpItEdeNSulo8bYsvil80Rl&utm_source=github&utm_medium=web&utm_campaign=nuclei_readme" target="_blank"><img src="/static/nuclei-getting-started.png" width="350px"></a> <a href="https://www.youtube.com/watch?v=nFXygQdtjyw&utm_source=github&utm_medium=web&utm_campaign=nuclei_readme" target="_blank"><img src="/static/nuclei-write-your-first-template.png" width="350px"></a>

</div>

<br>

### Installation

`nuclei` requires **go1.23** to install successfully. Run the following command to get the repo:

```sh
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

To learn more about installing nuclei, see `https://docs.projectdiscovery.io/tools/nuclei/install`.

### Command Line Flags

To display all the flags for the tool:

```sh
nuclei -h
```

<details>
  <summary>Expand full help flags</summary>

```yaml
Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.

Usage:
  ./nuclei [flags]

Flags:
TARGET:
   -u, -target string[]          target URLs/hosts to scan
   -l, -list string              path to file containing a list of target URLs/hosts to scan (one per line)
   -eh, -exclude-hosts string[]  hosts to exclude to scan from the input list (ip, cidr, hostname)
   -resume string                resume scan using resume.cfg (clustering will be disabled)
   -sa, -scan-all-ips            scan all the IP's associated with dns record
   -iv, -ip-version string[]     IP version to scan of hostname (4,6) - (default 4)

TARGET-FORMAT:
   -im, -input-mode string        mode of input file (list, burp, jsonl, yaml, openapi, swagger) (default "list")
   -ro, -required-only            use only required fields in input format when generating requests
   -sfv, -skip-format-validation  skip format validation (like missing vars) when parsing input file

TEMPLATES:
   -nt, -new-templates                    run only new templates added in latest nuclei-templates release
   -ntv, -new-templates-version string[]  run new templates added in specific version
   -as, -automatic-scan                   automatic web scan using wappalyzer technology detection to tags mapping
   -t, -templates string[]                list of template or template directory to run (comma-separated, file)
   -turl, -template-url string[]          template url or list containing template urls to run (comma-separated, file)
   -ai, -prompt string                    generate and run template using ai prompt
   -w, -workflows string[]                list of workflow or workflow directory to run (comma-separated, file)
   -wurl, -workflow-url string[]          workflow url or list containing workflow urls to run (comma-separated, file)
   -validate                              validate the passed templates to nuclei
   -nss, -no-strict-syntax                disable strict syntax check on templates
   -td, -template-display                 displays the templates content
   -tl                                    list all available templates
   -tgl                                   list all available tags
   -sign                                  signs the templates with the private key defined in NUCLEI_SIGNATURE_PRIVATE_KEY env variable
   -code                                  enable loading code protocol-based templates
   -dut, -disable-unsigned-templates      disable running unsigned templates or templates with mismatched signature
   -esc, -enable-self-contained           enable loading self-contained templates
   -egm, -enable-global-matchers          enable loading global matchers templates
   -file                                  enable loading file templates

FILTERING:
   -a, -author string[]               templates to run based on authors (comma-separated, file)
   -tags string[]                     templates to run based on tags (comma-separated, file)
   -etags, -exclude-tags string[]     templates to exclude based on tags (comma-separated, file)
   -itags, -include-tags string[]     tags to be executed even if they are excluded either by default or configuration
   -id, -template-id string[]         templates to run based on template ids (comma-separated, file, allow-wildcard)
   -eid, -exclude-id string[]         templates to exclude based on template ids (comma-separated, file)
   -it, -include-templates string[]   path to template file or directory to be executed even if they are excluded either by default or configuration
   -et, -exclude-templates string[]   path to template file or directory to exclude (comma-separated, file)
   -em, -exclude-matchers string[]    template matchers to exclude in result
   -s, -severity value[]              templates to run based on severity. Possible values: info, low, medium, high, critical, unknown
   -es, -exclude-severity value[]     templates to exclude based on severity. Possible values: info, low, medium, high, critical, unknown
   -pt, -type value[]                 templates to run based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -ept, -exclude-type value[]        templates to exclude based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -tc, -template-condition string[]  templates to run based on expression condition

OUTPUT:
   -o, -output string            output file to write found issues/vulnerabilities
   -sresp, -store-resp           store all request/response passed through nuclei to output directory
   -srd, -store-resp-dir string  store all request/response passed through nuclei to custom directory (default "output")
   -silent                       display findings only
   -nc, -no-color                disable output content coloring (ANSI escape codes)
   -j, -jsonl                    write output in JSONL(ines) format
   -irr, -include-rr -omit-raw   include request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only) [DEPRECATED use -omit-raw] (default true)
   -or, -omit-raw                omit request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only)
   -ot, -omit-template           omit encoded template in the JSON, JSONL output
   -nm, -no-meta                 disable printing result metadata in cli output
   -ts, -timestamp               enables printing timestamp in cli output
   -rdb, -report-db string       nuclei reporting database (always use this to persist report data)
   -ms, -matcher-status          display match failure status
   -me, -markdown-export string  directory to export results in markdown format
   -se, -sarif-export string     file to export results in SARIF format
   -je, -json-export string      file to export results in JSON format
   -jle, -jsonl-export string    file to export results in JSONL(ine) format
   -rd, -redact string[]         redact given list of keys from query parameter, request header and body

CONFIGURATIONS:
   -config string                        path to the nuclei configuration file
   -tp, -profile string                  template profile config file to run
   -tpl, -profile-list                   list community template profiles
   -fr, -follow-redirects                enable following redirects for http templates
   -fhr, -follow-host-redirects          follow redirects on the same host
   -mr, -max-redirects int               max number of redirects to follow for http templates (default 10)
   -dr, -disable-redirects               disable redirects for http templates
   -rc, -report-config string            nuclei reporting module configuration file
   -H, -header string[]                  custom header/cookie to include in all http request in header:value format (cli, file)
   -V, -var value                        custom vars in key=value format
   -r, -resolvers string                 file containing resolver list for nuclei
   -sr, -system-resolvers                use system DNS resolving as error fallback
   -dc, -disable-clustering              disable clustering of requests
   -passive                              enable passive HTTP response processing mode
   -fh2, -force-http2                    force http2 connection on requests
   -ev, -env-vars                        enable environment variables to be used in template
   -cc, -client-cert string              client certificate file (PEM-encoded) used for authenticating against scanned hosts
   -ck, -client-key string               client key file (PEM-encoded) used for authenticating against scanned hosts
   -ca, -client-ca string                client certificate authority file (PEM-encoded) used for authenticating against scanned hosts
   -sml, -show-match-line                show match lines for file templates, works with extractors only
   -ztls                                 use ztls library with autofallback to standard one for tls13 [Deprecated] autofallback to ztls is enabled by default
   -sni string                           tls sni hostname to use (default: input domain name)
   -dka, -dialer-keep-alive value        keep-alive duration for network requests.
   -lfa, -allow-local-file-access        allows file (payload) access anywhere on the system
   -lna, -restrict-local-network-access  blocks connections to the local / private network
   -i, -interface string                 network interface to use for network scan
   -at, -attack-type string              type of payload combinations to perform (batteringram,pitchfork,clusterbomb)
   -sip, -source-ip string               source ip address to use for network scan
   -rsr, -response-size-read int         max response size to read in bytes
   -rss, -response-size-save int         max response size to read in bytes (default 1048576)
   -reset                                reset removes all nuclei configuration and data files (including nuclei-templates)
   -tlsi, -tls-impersonate               enable experimental client hello (ja3) tls randomization
   -hae, -http-api-endpoint string       experimental http api endpoint

INTERACTSH:
   -iserver, -interactsh-server string  interactsh server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    authentication token for self-hosted interactsh server
   -interactions-cache-size int         number of requests to keep in the interactions cache (default 5000)
   -interactions-eviction int           number of seconds to wait before evicting requests from cache (default 60)
   -interactions-poll-duration int      number of seconds to wait before each interaction poll request (default 5)
   -interactions-cooldown-period int    extra time for interaction polling before exiting (default 5)
   -ni, -no-interactsh                  disable interactsh server for OAST testing, exclude OAST based templates

FUZZING:
   -ft, -fuzzing-type string           overrides fuzzing type set in template (replace, prefix, postfix, infix)
   -fm, -fuzzing-mode string           overrides fuzzing mode set in template (multiple, single)
   -fuzz                               enable loading fuzzing templates (Deprecated: use -dast instead)
   -dast                               enable / run dast (fuzz) nuclei templates
   -dts, -dast-server                  enable dast server mode (live fuzzing)
   -dtr, -dast-report                  write dast scan report to file
   -dtst, -dast-server-token string    dast server token (optional)
   -dtsa, -dast-server-address string  dast server address (default "localhost:9055")
   -dfp, -display-fuzz-points          display fuzz points in the output for debugging
   -fuzz-param-frequency int           frequency of uninteresting parameters for fuzzing before skipping (default 10)
   -fa, -fuzz-aggression string        fuzzing aggression level controls payload count for fuzz (low, medium, high) (default "low")
   -cs, -fuzz-scope string[]           in scope url regex to be followed by fuzzer
   -cos, -fuzz-out-scope string[]      out of scope url regex to be excluded by fuzzer

UNCOVER:
   -uc, -uncover                  enable uncover engine
   -uq, -uncover-query string[]   uncover search query
   -ue, -uncover-engine string[]  uncover search engine (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow,google) (default shodan)
   -uf, -uncover-field string     uncover fields to return (ip,port,host) (default "ip:port")
   -ul, -uncover-limit int        uncover results to return (default 100)
   -ur, -uncover-ratelimit int    override ratelimit of engines with unknown ratelimit (default 60 req/min) (default 60)

RATE-LIMIT:
   -rl, -rate-limit int               maximum number of requests to send per second (default 150)
   -rld, -rate-limit-duration value   maximum number of requests to send per second (default 1s)
   -rlm, -rate-limit-minute int       maximum number of requests to send per minute (DEPRECATED)
   -bs, -bulk-size int                maximum number of hosts to be analyzed in parallel per template (default 25)
   -c, -concurrency int               maximum number of templates to be executed in parallel (default 25)
   -hbs, -headless-bulk-size int      maximum number of headless hosts to be analyzed in parallel per template (default 10)
   -headc, -headless-concurrency int  maximum number of headless templates to be executed in parallel (default 10)
   -jsc, -js-concurrency int          maximum number of javascript runtimes to be executed in parallel (default 120)
   -pc, -payload-concurrency int      max payload concurrency for each template (default 25)
   -prc, -probe-concurrency int       http probe concurrency with httpx (default 50)

OPTIMIZATIONS:
   -timeout int                     time to wait in seconds before timeout (default 10)
   -retries int                     number of times to retry a failed request (default 1)
   -ldp, -leave-default-ports       leave default HTTP/HTTPS ports (eg. host:80,host:443)
   -mhe, -max-host-error int        max errors for a host before skipping from scan (default 30)
   -te, -track-error string[]       adds given error to max-host-error watchlist (standard, file)
   -nmhe, -no-mhe                   disable skipping host from scan based on errors
   -project                         use a project folder to avoid sending same request multiple times
   -project-path string             set a specific project path (default "/tmp")
   -spm, -stop-at-first-match       stop processing HTTP requests after the first match (may break template/workflow logic)
   -stream                          stream mode - start elaborating without sorting the input
   -ss, -scan-strategy value        strategy to use while scanning(auto/host-spray/template-spray) (default auto)
   -irt, -input-read-timeout value  timeout on input read (default 3m0s)
   -nh, -no-httpx                   disable httpx probing for non-url input
   -no-stdin                        disable stdin processing

HEADLESS:
   -headless                        enable templates that require headless browser support (root user on Linux will disable sandbox)
   -page-timeout int                seconds to wait for each page in headless mode (default 20)
   -sb, -show-browser               show the browser on the screen when running templates with headless mode
   -ho, -headless-options string[]  start headless chrome with additional options
   -sc, -system-chrome              use local installed Chrome browser instead of nuclei installed
   -lha, -list-headless-action      list available headless actions

DEBUG:
   -debug                     show all requests and responses
   -dreq, -debug-req          show all sent requests
   -dresp, -debug-resp        show all received responses
   -p, -proxy string[]        list of http/socks5 proxy to use (comma separated or file input)
   -pi, -proxy-internal       proxy all internal requests
   -ldf, -list-dsl-function   list all supported DSL function signatures
   -tlog, -trace-log string   file to write sent requests trace log
   -elog, -error-log string   file to write sent requests error log
   -version                   show nuclei version
   -hm, -hang-monitor         enable nuclei hang monitoring
   -v, -verbose               show verbose output
   -profile-mem string        generate memory (heap) profile & trace files
   -vv                        display templates loaded for scan
   -svd, -show-var-dump       show variables dump for debugging
   -vdl, -var-dump-limit int  limit the number of characters displayed in var dump (default 255)
   -ep, -enable-pprof         enable pprof debugging server
   -tv, -templates-version    shows the version of the installed nuclei-templates
   -hc, -health-check         run diagnostic check up

UPDATE:
   -up, -update                      update nuclei engine to the latest released version
   -ut, -update-templates            update nuclei-templates to latest released version
   -ud, -update-template-dir string  custom directory to install / update nuclei-templates
   -duc, -disable-update-check       disable automatic nuclei/templates update check

STATISTICS:
   -stats                    display statistics about the running scan
   -sj, -stats-json          display statistics in JSONL(ines) format
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)
   -mp, -metrics-port int    port to expose nuclei metrics on (default 9092)
   -hps, -http-stats         enable http status capturing (experimental)

CLOUD:
   -auth                           configure projectdiscovery cloud (pdcp) api key (default true)
   -tid, -team-id string           upload scan results to given team id (optional) (default "none")
   -cup, -cloud-upload             upload scan results to pdcp dashboard [DEPRECATED use -dashboard]
   -sid, -scan-id string           upload scan results to existing scan id (optional)
   -sname, -scan-name string       scan name to set (optional)
   -pd, -dashboard                 upload / view nuclei results in projectdiscovery cloud (pdcp) UI dashboard
   -pdu, -dashboard-upload string  upload / view nuclei results file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard

AUTHENTICATION:
   -sf, -secret-file string[]  path to config file containing secrets for nuclei authenticated scan
   -ps, -prefetch-secrets      prefetch secrets from the secrets file


EXAMPLES:
Run nuclei on single host:
	$ nuclei -target example.com

Run nuclei with specific template directories:
	$ nuclei -target example.com -t http/cves/ -t ssl

Run nuclei against a list of hosts:
	$ nuclei -list hosts.txt

Run nuclei with a JSON output:
	$ nuclei -target example.com -json-export output.json

Run nuclei with sorted Markdown outputs (with environment variables):
	$ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

Additional documentation is available at: https://docs.nuclei.sh/getting-started/running

```

Additional documentation is available at: [**`docs.nuclei.sh/getting-started/running`**](https://docs.nuclei.sh/getting-started/running?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme)

</details>

### Single target scan

To perform a quick scan on web-application:

```sh
nuclei -target https://example.com
```

### Scanning multiple targets

Nuclei can handle bulk scanning by providing a list of targets. You can use a file containing multiple URLs.

```sh
nuclei -list urls.txt
```

### Network scan

This will scan the entire subnet for network-related issues, such as open ports or misconfigured services.

```sh
nuclei -target 192.168.1.0/24
```

### Scanning with your custom template

To write and use your own template, create a `.yaml` file with specific rules, then use it as follows.

```sh
nuclei -u https://example.com -t /path/to/your-template.yaml
```

### Connect Nuclei to ProjectDiscovery

You can run the scans on your machine and upload the results to the cloud platform for further analysis and remediation.

```sh
nuclei -target https://example.com -dashboard
```

> [!NOTE]
> This feature is absolutely free and does not require any subscription. For a detailed guide, refer to the [**`documentation`**](https://docs.projectdiscovery.io/cloud/scanning/nuclei-scan?utm_source=github&utm_medium=web&utm_campaign=nuclei_readme).

<br>
<br>

## Nuclei Templates, Community and Rewards 💎
[**Nuclei templates**](https://github.com/projectdiscovery/nuclei-templates) are based on the concepts of YAML based template files that define how the requests will be sent and processed. This allows easy extensibility capabilities to nuclei. The templates are written in YAML which specifies a simple human-readable format to quickly define the execution process.

**Try it online with our free AI powered Nuclei Templates Editor by** [**`clicking here`**](https://cloud.projectdiscovery.io/templates).

Nuclei Templates offer a streamlined way to identify and communicate vulnerabilities, combining essential details like severity ratings and detection methods. This open-source, community-developed tool accelerates threat response and is widely recognized in the cybersecurity world. Nuclei templates are actively contributed by thousands of security researchers globally. We run two programs for our contributors: [**`Pioneers`**](https://projectdiscovery.io/pioneers) and [**`💎 bounties`**](https://github.com/projectdiscovery/nuclei-templates/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22%F0%9F%92%8E%20Bounty%22).


<p align="left">
    <a href="/static/nuclei-templates-teamcity.png"  target="_blank"><img src="/static/nuclei-templates-teamcity.png" width="1200px" alt="Nuclei template example for detecting TeamCity misconfiguration" /></a>
</p>

#### Examples

Visit [**our documentation**](https://docs.projectdiscovery.io/templates/introduction) for use cases and ideas.

| Use case                             | Nuclei template                                    |
| :----------------------------------- | :------------------------------------------------- |
| Detect known CVEs                    | **[CVE-2021-44228 (Log4Shell)](https://cloud.projectdiscovery.io/public/CVE-2021-45046)**                     |
| Identify Out-of-Band vulnerabilities | **[Blind SQL Injection via OOB](https://cloud.projectdiscovery.io/public/CVE-2024-22120)**                    |
| SQL Injection detection              | **[Generic SQL Injection](https://cloud.projectdiscovery.io/public/CVE-2022-34265)**                          |
| Cross-Site Scripting (XSS)           | **[Reflected XSS Detection](https://cloud.projectdiscovery.io/public/CVE-2023-4173)**                        |
| Default or weak passwords            | **[Default Credentials Check](https://cloud.projectdiscovery.io/public/airflow-default-login)**                      |
| Secret files or data exposure        | **[Sensitive File Disclosure](https://cloud.projectdiscovery.io/public/airflow-configuration-exposure)**                      |
| Identify open redirects              | **[Open Redirect Detection](https://cloud.projectdiscovery.io/public/open-redirect)**                        |
| Detect subdomain takeovers           | **[Subdomain Takeover Templates](https://cloud.projectdiscovery.io/public/azure-takeover-detection)**                   |
| Security misconfigurations           | **[Unprotected Jenkins Console](https://cloud.projectdiscovery.io/public/unauthenticated-jenkins)**                    |
| Weak SSL/TLS configurations          | **[SSL Certificate Expiry](https://cloud.projectdiscovery.io/public/expired-ssl)**                         |
| Misconfigured cloud services         | **[Open S3 Bucket Detection](https://cloud.projectdiscovery.io/public/s3-public-read-acp)**                       |
| Remote code execution vulnerabilities| **[RCE Detection Templates](https://cloud.projectdiscovery.io/public/CVE-2024-29824)**                        |
| Directory traversal attacks          | **[Path Traversal Detection](https://cloud.projectdiscovery.io/public/oracle-fatwire-lfi)**                       |
| File inclusion vulnerabilities       | **[Local/Remote File Inclusion](https://cloud.projectdiscovery.io/public/CVE-2023-6977)**                    |


<br>
<br>

## Our Mission

Traditional vulnerability scanners were built decades ago. They are closed-source, incredibly slow, and vendor-driven. Today's attackers are mass exploiting newly released CVEs across the internet within days, unlike the years it used to take. This shift requires a completely different approach to tackling trending exploits on the internet.

We built Nuclei to solve this challenge. We made the entire scanning engine framework open and customizable—allowing the global security community to collaborate and tackle the trending attack vectors and vulnerabilities on the internet. Nuclei is now used and contributed by Fortune 500 enterprises, government agencies, universities.

You can participate by contributing to our code, [**`templates library`**](https://github.com/projectdiscovery/nuclei-templates), or [**`joining our team`**](https://projectdiscovery.io/).

<br>
<br>

## Contributors :heart:

Thanks to all the amazing [**`community contributors for sending PRs`**](https://github.com/projectdiscovery/nuclei/graphs/contributors) and keeping this project updated. :heart:

<p align="left">
<a href="https://github.com/Ice3man543"><img src="https://avatars.githubusercontent.com/u/22318055?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/apps/dependabot"><img src="https://avatars.githubusercontent.com/in/29110?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ehsandeep"><img src="https://avatars.githubusercontent.com/u/8293321?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Mzack9999"><img src="https://avatars.githubusercontent.com/u/13421144?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/forgedhallpass"><img src="https://avatars.githubusercontent.com/u/13679401?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/tarunKoyalwar"><img src="https://avatars.githubusercontent.com/u/45962551?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/manuelbua"><img src="https://avatars.githubusercontent.com/u/819314?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/actions-user"><img src="https://avatars.githubusercontent.com/u/65916846?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/dogancanbakir"><img src="https://avatars.githubusercontent.com/u/65292895?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/parrasajad"><img src="https://avatars.githubusercontent.com/u/16835787?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/vzamanillo"><img src="https://avatars.githubusercontent.com/u/10209695?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ShubhamRasal"><img src="https://avatars.githubusercontent.com/u/45902122?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/RamanaReddy0M"><img src="https://avatars.githubusercontent.com/u/90540245?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/LuitelSamikshya"><img src="https://avatars.githubusercontent.com/u/85764322?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/kchason"><img src="https://avatars.githubusercontent.com/u/1111099?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/pmareke"><img src="https://avatars.githubusercontent.com/u/3502075?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/dwisiswant0"><img src="https://avatars.githubusercontent.com/u/25837540?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/xm1k3"><img src="https://avatars.githubusercontent.com/u/73166077?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/5amu"><img src="https://avatars.githubusercontent.com/u/39925709?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ehrishirajsharma"><img src="https://avatars.githubusercontent.com/u/35542790?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/zerodivisi0n"><img src="https://avatars.githubusercontent.com/u/687694?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/geeknik"><img src="https://avatars.githubusercontent.com/u/466878?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/TerminalFi"><img src="https://avatars.githubusercontent.com/u/32599364?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/KaulSe"><img src="https://avatars.githubusercontent.com/u/45340011?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/sullo"><img src="https://avatars.githubusercontent.com/u/1474884?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/wdahlenburg"><img src="https://avatars.githubusercontent.com/u/4451504?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ghost"><img src="https://avatars.githubusercontent.com/u/10137?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Nishan8583"><img src="https://avatars.githubusercontent.com/u/20457968?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/jdk2588"><img src="https://avatars.githubusercontent.com/u/985054?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/nothinux"><img src="https://avatars.githubusercontent.com/u/17433202?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/CodFrm"><img src="https://avatars.githubusercontent.com/u/22783163?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/CasperGN"><img src="https://avatars.githubusercontent.com/u/5549643?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ankh2054"><img src="https://avatars.githubusercontent.com/u/6784287?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/revblock"><img src="https://avatars.githubusercontent.com/u/72813848?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/cn-kali-team"><img src="https://avatars.githubusercontent.com/u/30642514?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/EndPositive"><img src="https://avatars.githubusercontent.com/u/25148195?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/jimen0"><img src="https://avatars.githubusercontent.com/u/6826244?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/xstevens"><img src="https://avatars.githubusercontent.com/u/69216?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/mjkim610"><img src="https://avatars.githubusercontent.com/u/17107206?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/organiccrap"><img src="https://avatars.githubusercontent.com/u/376317?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/lu4nx"><img src="https://avatars.githubusercontent.com/u/3006875?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/souvikhazra1"><img src="https://avatars.githubusercontent.com/u/13842393?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/tovask"><img src="https://avatars.githubusercontent.com/u/22732484?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Marmelatze"><img src="https://avatars.githubusercontent.com/u/199681?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/doug-threatmate"><img src="https://avatars.githubusercontent.com/u/127235272?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/yabeow"><img src="https://avatars.githubusercontent.com/u/21117771?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/olearycrew"><img src="https://avatars.githubusercontent.com/u/6044920?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/gano3s"><img src="https://avatars.githubusercontent.com/u/2551605?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/alizmhdi"><img src="https://avatars.githubusercontent.com/u/79321261?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/hackerpain"><img src="https://avatars.githubusercontent.com/u/61242234?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/lc"><img src="https://avatars.githubusercontent.com/u/19563282?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/savushkin-yauheni"><img src="https://avatars.githubusercontent.com/u/5173352?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/74616e696d"><img src="https://avatars.githubusercontent.com/u/97121933?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/edoardottt"><img src="https://avatars.githubusercontent.com/u/35783570?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/zt2"><img src="https://avatars.githubusercontent.com/u/7644862?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/moonD4rk"><img src="https://avatars.githubusercontent.com/u/24284231?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/wk8"><img src="https://avatars.githubusercontent.com/u/2536231?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/mikerott"><img src="https://avatars.githubusercontent.com/u/857712?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/toufik-airane"><img src="https://avatars.githubusercontent.com/u/5610269?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/hktalent"><img src="https://avatars.githubusercontent.com/u/18223385?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/jturner"><img src="https://avatars.githubusercontent.com/u/1825202?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/gaby"><img src="https://avatars.githubusercontent.com/u/835733?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/vavkamil"><img src="https://avatars.githubusercontent.com/u/47953210?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/leonjza"><img src="https://avatars.githubusercontent.com/u/1148127?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/mionskowski-form3"><img src="https://avatars.githubusercontent.com/u/91873652?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/chenrui333"><img src="https://avatars.githubusercontent.com/u/1580956?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/iamargus95"><img src="https://avatars.githubusercontent.com/u/77744293?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/shashikarsiddharth"><img src="https://avatars.githubusercontent.com/u/60960197?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/trypa11"><img src="https://avatars.githubusercontent.com/u/67585616?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Zeokat"><img src="https://avatars.githubusercontent.com/u/1313154?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/alban-stourbe-wmx"><img src="https://avatars.githubusercontent.com/u/159776828?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/anykno"><img src="https://avatars.githubusercontent.com/u/2528207?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ronaudinho"><img src="https://avatars.githubusercontent.com/u/10264710?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/boy-hack"><img src="https://avatars.githubusercontent.com/u/18695984?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/iuliu8899"><img src="https://avatars.githubusercontent.com/u/31680027?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/debasishbsws"><img src="https://avatars.githubusercontent.com/u/65381620?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/denysvitali-niantic"><img src="https://avatars.githubusercontent.com/u/157139422?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/fail-open"><img src="https://avatars.githubusercontent.com/u/72417455?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Xc1Ym"><img src="https://avatars.githubusercontent.com/u/29765332?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/XTeam-Wing"><img src="https://avatars.githubusercontent.com/u/25416365?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Weltolk"><img src="https://avatars.githubusercontent.com/u/40228052?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/tonghuaroot"><img src="https://avatars.githubusercontent.com/u/23011166?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/praetorian-thendrickson"><img src="https://avatars.githubusercontent.com/u/69640071?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/S0obi"><img src="https://avatars.githubusercontent.com/u/4180104?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/skahn007gl"><img src="https://avatars.githubusercontent.com/u/144735608?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/shouichi"><img src="https://avatars.githubusercontent.com/u/99586?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/seb-elttam"><img src="https://avatars.githubusercontent.com/u/111818823?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/AdallomRoy"><img src="https://avatars.githubusercontent.com/u/4046118?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/rotemreiss"><img src="https://avatars.githubusercontent.com/u/9288082?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/oscarintherocks"><img src="https://avatars.githubusercontent.com/u/1785821?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/xxcdd"><img src="https://avatars.githubusercontent.com/u/42600601?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/chen2aaron"><img src="https://avatars.githubusercontent.com/u/9978183?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/voidz0r"><img src="https://avatars.githubusercontent.com/u/1032286?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/vince-isec"><img src="https://avatars.githubusercontent.com/u/149686094?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/true13"><img src="https://avatars.githubusercontent.com/u/18207552?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/skhalsa-sigsci"><img src="https://avatars.githubusercontent.com/u/68570441?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ShuBo6"><img src="https://avatars.githubusercontent.com/u/41125338?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/seeyarh"><img src="https://avatars.githubusercontent.com/u/16869800?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/securibee"><img src="https://avatars.githubusercontent.com/u/51520913?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/sduc"><img src="https://avatars.githubusercontent.com/u/2879617?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/scottdharvey"><img src="https://avatars.githubusercontent.com/u/25498254?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/rykkard"><img src="https://avatars.githubusercontent.com/u/51889048?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/monitor403"><img src="https://avatars.githubusercontent.com/u/45124775?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/mlec1"><img src="https://avatars.githubusercontent.com/u/42201667?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/meme-lord"><img src="https://avatars.githubusercontent.com/u/17912559?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/LazyMaple"><img src="https://avatars.githubusercontent.com/u/12314941?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/lvyaoting"><img src="https://avatars.githubusercontent.com/u/166296299?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/llussy"><img src="https://avatars.githubusercontent.com/u/18432966?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/linchizhen"><img src="https://avatars.githubusercontent.com/u/170242051?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/kiokuless"><img src="https://avatars.githubusercontent.com/u/110003596?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Jarnpher553"><img src="https://avatars.githubusercontent.com/u/10233873?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/c-f"><img src="https://avatars.githubusercontent.com/u/35263248?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/hanghuge"><img src="https://avatars.githubusercontent.com/u/166206050?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/testwill"><img src="https://avatars.githubusercontent.com/u/8717479?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/galoget"><img src="https://avatars.githubusercontent.com/u/8353133?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/fudancoder"><img src="https://avatars.githubusercontent.com/u/171416994?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/revolunet"><img src="https://avatars.githubusercontent.com/u/124937?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/jsoref"><img src="https://avatars.githubusercontent.com/u/2119212?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/MachadoOtto"><img src="https://avatars.githubusercontent.com/u/93268441?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/jonathanwalker"><img src="https://avatars.githubusercontent.com/u/14978093?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/nHurD"><img src="https://avatars.githubusercontent.com/u/233374?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/jessekelly881"><img src="https://avatars.githubusercontent.com/u/22938931?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/JaneX8"><img src="https://avatars.githubusercontent.com/u/5116641?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/eltociear"><img src="https://avatars.githubusercontent.com/u/22633385?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/atomiczsec"><img src="https://avatars.githubusercontent.com/u/75549184?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/M-Faheem-Khan"><img src="https://avatars.githubusercontent.com/u/17150767?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/denandz"><img src="https://avatars.githubusercontent.com/u/5291556?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/tibbon"><img src="https://avatars.githubusercontent.com/u/82880?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/dany74q"><img src="https://avatars.githubusercontent.com/u/2129762?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/0x123456789"><img src="https://avatars.githubusercontent.com/u/36066426?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/danigoland"><img src="https://avatars.githubusercontent.com/u/15079567?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/ChrisMandich"><img src="https://avatars.githubusercontent.com/u/14286797?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/austintraver"><img src="https://avatars.githubusercontent.com/u/25112463?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/socialsister"><img src="https://avatars.githubusercontent.com/u/155628741?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Anemys"><img src="https://avatars.githubusercontent.com/u/51196227?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/andreangelucci"><img src="https://avatars.githubusercontent.com/u/18552197?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/AlexS778"><img src="https://avatars.githubusercontent.com/u/98418121?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/noraj"><img src="https://avatars.githubusercontent.com/u/16578570?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/akkuman"><img src="https://avatars.githubusercontent.com/u/7813511?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/zrquan"><img src="https://avatars.githubusercontent.com/u/33086594?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/1efty"><img src="https://avatars.githubusercontent.com/u/18194777?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/rsrdesarrollo"><img src="https://avatars.githubusercontent.com/u/5142014?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/razin99"><img src="https://avatars.githubusercontent.com/u/44442082?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/MetzinAround"><img src="https://avatars.githubusercontent.com/u/65838556?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/vil02"><img src="https://avatars.githubusercontent.com/u/65706193?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/mrschyte"><img src="https://avatars.githubusercontent.com/u/8571?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/PeterDaveHello"><img src="https://avatars.githubusercontent.com/u/3691490?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/parthmalhotra"><img src="https://avatars.githubusercontent.com/u/28601533?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/owenrumney"><img src="https://avatars.githubusercontent.com/u/3049157?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Ovi3"><img src="https://avatars.githubusercontent.com/u/29408109?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/Bisstocuz"><img src="https://avatars.githubusercontent.com/u/42398278?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/daffainfo"><img src="https://avatars.githubusercontent.com/u/36522826?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/mhmdiaa"><img src="https://avatars.githubusercontent.com/u/19687798?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/MiryangJung"><img src="https://avatars.githubusercontent.com/u/48237511?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/0xmin"><img src="https://avatars.githubusercontent.com/u/44919834?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/maikthulhu"><img src="https://avatars.githubusercontent.com/u/680830?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/sttlr"><img src="https://avatars.githubusercontent.com/u/40246850?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/iamRjarpan"><img src="https://avatars.githubusercontent.com/u/45498226?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/leoloobeek"><img src="https://avatars.githubusercontent.com/u/8801754?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/KristinnVikar"><img src="https://avatars.githubusercontent.com/u/93918469?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/kant01ne"><img src="https://avatars.githubusercontent.com/u/5072452?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/KeisukeYamashita"><img src="https://avatars.githubusercontent.com/u/23056537?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
<a href="https://github.com/1hehaq"><img src="https://avatars.githubusercontent.com/u/162917546?v=4" width="50" height="50" alt="" style="max-width: 100%;"></a>
</p>

<br>
<br>
<br>

<div align="center">
  
  <sub>**`nuclei`** is distributed under [**MIT License**](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)</sub>

</div>
