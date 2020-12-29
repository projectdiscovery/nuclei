<h1 align="center">
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

<p align="center">
<a href="https://nuclei.projectdiscovery.io/templating-guide/" target="_blank"><img src="static/read-the-docs-button.png" height="42px"/></center></a>  <a href="https://github.com/projectdiscovery/nuclei-templates" target="_blank"><img src="static/download-templates-button.png" height="42px"/></a>
</p>


Nuclei is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use.

Nuclei is used to send requests across targets based on a template leading to zero false positives and providing effective scanning for known paths. Main use cases for nuclei are during initial reconnaissance phase to quickly check for low hanging fruits or CVEs across targets that are known and easily detectable. It uses [retryablehttp-go library](https://github.com/projectdiscovery/retryablehttp-go) designed to handle various errors and retries in case of blocking by WAFs, this is also one of our core modules from custom-queries.

We have also [open-sourced a template repository](https://github.com/projectdiscovery/nuclei-templates) to maintain various type of templates, we hope that you will contribute there too. Templates are provided in hopes that these will be useful and will allow everyone to build their own templates for the scanner. Checkout the templating guide at [**nuclei.projectdiscovery.io**](https://nuclei.projectdiscovery.io/templating-guide/) for a primer on nuclei templates.

## Resources

-   [Features](#features)
-   [Installation Instructions](#installation-instructions)
-   [Nuclei templates](#nuclei-templates)
-   [Usage](#usage)
-   [Running nuclei](#running-nuclei)
-   [Rate Limits](#rate-limits)
-   [Template exclusion](#template-exclusion)
-   [Acknowledgments](#acknowledgments)


## Features

<h1 align="left">
  <img src="static/nuclei-run.png" alt="nuclei" width="700px"></a>
  <br>
</h1>

-   Simple and modular code base making it easy to contribute.
-   Fast And fully configurable using a template based engine.
-   Handles edge cases doing retries, backoffs etc for handling WAFs.
-   Smart matching functionality for zero false positive scanning.


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
▶ GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

### From Github

```sh
▶ git clone https://github.com/projectdiscovery/nuclei.git; cd nuclei/v2/cmd/nuclei/; go build; mv nuclei /usr/local/bin/; nuclei -version
```

## Nuclei templates

You can download and update the nuclei templates using `update-templates` flag, `update-templates` flag downloads the latest release from **nuclei-templates** [Github project](https://github.com/projectdiscovery/nuclei-templates), a community curated list of templates that are ready to use.

```sh
▶ nuclei -update-templates
```

Additionally, you can write your own checks for your specific workflow and needs, please refer to **nuclei [templating guide](https://nuclei.projectdiscovery.io/templating-guide/) to write your own custom templates.**

## Usage

```sh
nuclei -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag                   | Description                                               | Example                                         |
| ---------------------- | --------------------------------------------------------- | ----------------------------------------------- |
| bulk-size              | Max hosts analyzed in parallel per template ( default 25) | nuclei -bulk-size 25                            |
| burp-collaborator-biid | Burp Collaborator BIID                                    | nuclei -burp-collaborator-biid XXXX             |
| c                      | Max templates processed in parallel (default 10)          | nuclei -c 10                                    |
| l                      | List of urls to run templates                             | nuclei -l urls.txt                              |
| target                 | Target to scan using Templates                            | nuclei -target hxxps://example.com              |
| t                      | Templates input file/files to check across hosts          | nuclei -t git-core.yaml -t cves/                |
| no-color               | Don't Use colors in output                                | nuclei -no-color                                |
| no-meta                | Don't display metadata for the matches                    | nuclei -no-meta                                 |
| json                   | Prints and write output in json format                    | nuclei -json                                    |
| include-rr             | Inlcude req/resp of matched output in JSON output         | nuclei -json -include-rr                        |
| o                      | File to save output result (optional)                     | nuclei -o output.txt                            |
| project                | Project flag to avoid sending same requests               | nuclei -project                                 |
| project-path           | Use a user defined project folder                         | nuclei -project -project-path test              |
| stats                  | Enable the progress bar (optional)                        | nuclei -stats                                   |
| silent                 | Show only found results in output                         | nuclei -silent                                  |
| retries                | Number of times to retry a failed request                 | nuclei -retries 1                               |
| timeout                | Seconds to wait before timeout (default 5)                | nuclei -timeout 5                               |
| trace-log              | File to write sent requests trace log                     | nuclei -trace-log logs                          |
| rate-limit             | Maximum requests/second (default 150)                     | nuclei -rate-limit 150                          |
| severity               | Run templates based on severity                           | nuclei -severity critical,high                  |
| stop-at-first-match    | Stop processing http requests at first match              | nuclei -stop-at-first-match                     |
| exclude                | Template input dir/file/files to exclude                  | nuclei -exclude panels -exclude tokens          |
| debug                  | Allow debugging of request/responses.                     | nuclei -debug                                   |
| update-templates       | Download and updates nuclei templates                     | nuclei -update-templates                        |
| update-directory       | Directory for storing nuclei-templates(optional)          | nuclei -update-directory templates              |
| tl                     | List available templates                                  | nuclei -tl                                      |
| templates-version      | Shows the installed nuclei-templates version              | nuclei -templates-version                       |
| v                      | Shows verbose output of all sent requests                 | nuclei -v                                       |
| version                | Show version of nuclei                                    | nuclei -version                                 |
| proxy-url              | Proxy URL                                                 | nuclei -proxy-url hxxp://127.0.0.1:8080         |
| proxy-socks-url        | Socks proxyURL                                            | nuclei -proxy-socks-url socks5://127.0.0.1:8080 |
| random-agent           | Use random User-Agents                                    | nuclei -random-agent                            |
| H                      | Custom Header                                             | nuclei -H "x-bug-bounty: hacker"                |

## Running Nuclei

### Running with single template.

This will run `git-core.yaml` template against all the hosts in `urls.txt` and returns the matched results.

```sh
▶ nuclei -l urls.txt -t files/git-core.yaml -o results.txt
```

You can also pass the list of urls at standard input (STDIN). This allows for easy integration in automation pipelines.

```sh
▶ cat urls.txt | nuclei -t files/git-core.yaml -o results.txt
```

💡 Nuclei accepts list of URLs as input, for example here is how `urls.txt` looks like:- 

```
https://test.some-site.com
http://vuls-testing.com
https://test.com
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
▶ cat urls.txt | docker run -v /path/to/nuclei-templates:/app/nuclei-templates -v /path/to/nuclei/config:/app/.nuclei-config.json -i projectdiscovery/nuclei -t /app/nuclei-templates/files/git-config.yaml > results.txt
```

Remember to change `/path-to-nuclei-templates` to the real path on your host file system.

### Rate Limits

Nuclei have multiple rate limit controls for multiple factors including a number of templates to execute in parallel, a number of hosts to be scanned in parallel for each template, and the global number of request / per second you wanted to make/limit using nuclei, as an example here is how all this can be controlled using flags.


- `-c` flag => Limits the number of templates processed in parallel.
- `-bulk-size` flag => Limits the number of hosts processed in parallel for each template.
- `-rate-limit` flag => Global rate limiter that ensures defined number of requests/second across all templates.

If you wanted go fast or control the scans, feel free to play with these flags and numbers, `rate-limit` always ensure to control the outgoing requests regardless the other flag you are using.

### Template Exclusion

[Nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) includes multiple checks including many that are useful for attack surface mapping and not necessarily a security issue, in cases where you only looking to scan few specific templates or directory, here are few options / flags to filter or exclude them from running.

#### Running templates with exclusion

We do not suggest running all the nuclei-templates directory at once, in case of doing so, one can make use of `exclude` flag to exclude specific directory or templates to ignore from scanning. 

```sh
nuclei -l urls.txt -t nuclei-templates -exclude panels/ -exclude technologies -exclude files/wp-xmlrpc.yaml
```

Note:- both directory and specific templates case be excluded from scan as shared in the above example.

#### Running templates based on severity

You can run the templates based on the specific severity of the template, single and multiple severity can be used for scan. 

```sh
nuclei -l urls.txt -t cves/ -severity critical,medium
```

The above example will run all the templates under `cves` directory with `critical` and `medium` severity. 

```sh
nuclei -l urls.txt -t panels/ -t technologies -severity info
```

The above example will run all the templates under `panels` and `technologies` directory with **severity** marked as `info`

#### Using `.nuclei-ignore` file for template exclusion

Since release of nuclei [v2.1.1](https://github.com/projectdiscovery/nuclei/releases/tag/v2.1.1), we have added support of `.nuclei-ignore` file that works along with `update-templates` flag of nuclei, in **.nuclei-ignore** file, you can define all the template directory or template path that you wanted to exclude from all the nuclei scans, to start using this feature, make sure you installed nuclei templates using `nuclei -update-templates` flag, now you can add/update/remove templates in the file that you wanted to exclude from running. 

```
nano ~/nuclei-templates/.nuclei-ignore
```

Default **nuclei-ignore** list can be accessed from [here](https://github.com/projectdiscovery/nuclei-templates/blob/master/.nuclei-ignore), in case you don't want to exclude anything, simply remove the `.nuclei-ignore` file.

* * *

### 📋 Notes

- Progress bar is experimental feature, might not work in few cases. 
- Progress bar doesn't work with workflows, numbers are not accurate due to conditional execution.


## Acknowledgments

Do also check out these similar awesome projects that may fit in your workflow:

[Burp Suite](https://portswigger.net/burp), [FFuF](https://github.com/ffuf/ffuf), [Jaeles](https://github.com/jaeles-project/jaeles), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [ChopChop](https://github.com/michelin/ChopChop)

--------

nuclei is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/nuclei/blob/master/THANKS.md)** file for more details.
