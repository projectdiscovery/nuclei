<h1 align="left">
  <img src="static/nuclei-logo.png" alt="nuclei" width="200px"></a>
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/nuclei)](https://goreportcard.com/report/github.com/projectdiscovery/nuclei)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/nuclei/issues)
[![GitHub Release](https://img.shields.io/github/release/projectdiscovery/nuclei)](https://github.com/projectdiscovery/nuclei/releases)
[![Follow on Twitter](https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter)](https://twitter.com/pdnuclei)
[![Docker Images](https://img.shields.io/docker/pulls/projectdiscovery/nuclei.svg)](https://hub.docker.com/r/projectdiscovery/nuclei)
[![Chat on Discord](https://img.shields.io/discord/695645237418131507.svg?logo=discord)](https://discord.gg/KECAGdH)

Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use.

Nuclei is used to send requests across targets based on a template leading to zero false positives and providing effective scanning for known paths. Main use cases for nuclei are during initial reconnaissance phase to quickly check for low hanging fruits or CVEs across targets that are known and easily detectable. It uses [retryablehttp-go library](https://github.com/projectdiscovery/retryablehttp-go) designed to handle various errors and retries in case of blocking by WAFs, this is also one of our core modules from custom-queries.

We have also [open-sourced a template repository](https://github.com/projectdiscovery/nuclei-templates) to maintain various type of templates, we hope that you will contribute there too. Templates are provided in hopes that these will be useful and will allow everyone to build their own templates for the scanner. Checkout the templating guide at [**nuclei.projectdiscovery.io**](https://nuclei.projectdiscovery.io/templating-guide/) for a primer on nuclei templates.

## Resources

<details>
<summary>Resources</summary>

-   [Features](#features)
-   [Usage](#usage)
-   [Installation Instructions](#installation-instructions)
    -   [From Binary](#from-binary)
    -   [From Source](#from-source)
    -   [From Github](#from-github)
-   [Nuclei templates](#nuclei-templates)
-   [Running nuclei](#running-nuclei)
    -   [Running with a single template.](#running-with-single-template)
    -   [Running with multiple templates.](#running-with-multiple-templates)
    -   [Running with subfinder](#running-with-subfinder)
    -   [Running in Docker](#running-in-docker-container)
-   [Thanks](#thanks)

</details>

## Features

<h1 align="left">
  <img src="static/nuclei-run.png" alt="nuclei" width="700px"></a>
  <br>
</h1>

-   Simple and modular code base making it easy to contribute.
-   Fast And fully configurable using a template based engine.
-   Handles edge cases doing retries, backoffs etc for handling WAFs.
-   Smart matching functionality for zero false positive scanning.

## Usage

```sh
nuclei -h
```

This will display help for the tool. Here are all the switches it supports.

|        Flag       |                      Description                      |                     Example                     |
| :---------------: | :---------------------------------------------------: | :---------------------------------------------: |
|         -c        |       Number of concurrent requests (default 10)      |                  nuclei -c 100                  |
|         -l        |             List of urls to run templates             |                nuclei -l urls.txt               |
|      -target      |             Target to scan using templates            |        nuclei -target hxxps://example.com       |
|         -t        |    Templates input file/files to check across hosts   |             nuclei -t git-core.yaml             |
|         -t        |    Templates input file/files to check across hosts   |         nuclei -t nuclei-templates/cves/        |
|        -nC        |               Don't Use colors in output              |                    nuclei -nC                   |
|       -json       |         Prints and write output in json format        |                   nuclei -json                  |
|   -json-requests  |  Write requests/responses for matches in JSON output  |           nuclei -json -json-requests           |
|         -o        |         File to save output result (optional)         |               nuclei -o output.txt              |
|       -pbar       |           Enable the progress bar (optional)          |                   nuclei -pbar                  |
|      -silent      |           Show only found results in output           |                  nuclei -silent                 |
|                   |             (except when using with pbar)             |                                                 |
|      -retries     | Number of times to retry a failed request (default 1) |                nuclei -retries 1                |
|      -timeout     |       Seconds to wait before timeout (default 5)      |                nuclei -timeout 5                |
|      -rl          |       Rate-Limit of requests per specified target     |                nuclei -rl 100                   |
|      -severity    |Filter templates based on their severity and only run the matching ones|                nuclei -severity critical, low                |
|      -exclude     |Template input dir/file/files to exclude               |                nuclei -exclude panels, tokens           |
|       -debug      |         Allow debugging of request/responses.         |                  nuclei -debug                  |
| -update-templates |         Download and updates nuclei templates         |             nuclei -update-templates            |
| -update-directory |    Directory for storing nuclei-templates(optional)   |        nuclei -update-directory templates       |
|        -tl        |                List available templates               |                    nuclei -tl                   |
|         -v        |       Shows verbose output of all sent requests       |                    nuclei -v                    |
|      -version     |                 Show version of nuclei                |                 nuclei -version                 |
|     -proxy-url    |                       Proxy URL                       |     nuclei -proxy-url hxxp://127.0.0.1:8080     |
|  -proxy-socks-url |                    Socks proxy  URL                   | nuclei -proxy-socks-url socks5://127.0.0.1:8080 |
|         -H        |                     Custom Header                     |         nuclei -H "x-bug-bounty: hacker"        |

## Installation Instructions

### From Binary

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/projectdiscovery/nuclei/releases/) page. Extract them using tar, move it to your `$PATH`and you're ready to go.

```sh
Download latest binary from https://github.com/projectdiscovery/nuclei/releases

▶ tar -xzvf nuclei-linux-amd64.tar.gz
▶ mv nuclei /usr/local/bin/
▶ nuclei -version
```

### From Source

nuclei requires **go1.14+** to install successfully. Run the following command to get the repo -

```sh
▶ GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

### From Github

```sh
▶ git clone https://github.com/projectdiscovery/nuclei.git; cd nuclei/v2/cmd/nuclei/; go build; mv nuclei /usr/local/bin/; nuclei -h
```

## Nuclei templates

You can download or update the nuclei templates using `update-templates` flag.

```sh
▶ nuclei -update-templates
```

or download it from [nuclei templates](https://github.com/projectdiscovery/nuclei-templates) Github project.

```sh
▶ git clone https://github.com/projectdiscovery/nuclei-templates.git
```

**Please refer to nuclei [templating guide](https://nuclei.projectdiscovery.io/templating-guide/) to writing your own custom templates.**

## Running nuclei

### Running with single template.

This will run `git-core.yaml` template against all the hosts in `urls.txt` and returns the matched results.

```sh
▶ nuclei -l urls.txt -t files/git-core.yaml -o results.txt
```

You can also pass the list of urls at standard input (STDIN). This allows for easy integration in automation pipelines.

```sh
▶ cat urls.txt | nuclei -t files/git-core.yaml -o results.txt
```

### Running with multiple templates.

This will run the tool against all the urls in `urls.txt` with all the templates in the `cves` and `files` directory and returns the matched results.

```sh
▶ nuclei -l urls.txt -t cves/ -t files/ -o results.txt
```

### Running with subfinder.

```sh
▶ subfinder -d hackerone.com -silent | httpx -silent | nuclei -t cves/ -o results.txt
```

### Running in Docker container

You can use the [nuclei dockerhub image](https://hub.docker.com/r/projectdiscovery/nuclei). Simply run -

```sh
▶ docker pull projectdiscovery/nuclei
```

After downloading or building the container, run the following:

```sh
▶ docker run -it projectdiscovery/nuclei
```

For example, this will run the tool against all the hosts in `urls.txt` and output the results to your host file system:

```sh
▶ cat urls.txt | docker run -v /path-to-nuclei-templates:/go/src/app/ -i projectdiscovery/nuclei -t ./files/git-config.yaml > results.txt
```

Remember to change `/path-to-nuclei-templates` to the real path on your host file system.

* * *

## Thanks

nuclei is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/nuclei/blob/master/THANKS.md)** file for more details.

Do also check out these similar awesome projects that may fit in your workflow:

[Burp Suite](https://portswigger.net/burp), [FFuF](https://github.com/ffuf/ffuf), [Jaeles](https://github.com/jaeles-project/jaeles), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [ChopChop](https://github.com/michelin/ChopChop)
