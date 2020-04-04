<h1 align="left">
  <img src="static/nuclei-logo.png" alt="nuclei" width="200px"></a>
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/nuclei)](https://goreportcard.com/report/github.com/projectdiscovery/nuclei)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/nuclei/issues)

Nuceli is a fast tool for configurable targeted scanning based on templates offering massive extensibility and ease of use. 

Nuclei is used to send requests across targets based on a template leading to zero false positives and providing effective scanning for known paths. Main use cases for nuclei are during initial reconnaissance phase to quickly check for low hanging fruits or CVEs across targets that are known and easily detectable. It uses [retryablehttp-go library](https://github.com/projectdiscovery/retryablehttp-go) designed to handle various errors and retries in case of blocking by WAFs, this is also one of our core modules from custom-queries.

We have also [open-sourced a dedicated repository](https://github.com/projectdiscovery/nuclei-templates) to maintain various type of templates, we hope that you will contribute there too. Templates are provided in hopes that these will be useful and will allow everyone to build their own templates for the scanner. 

# Resources
- [Resources](#resources)
- [Features](#features)
- [Usage](#usage)
- [Installation Instructions](#installation-instructions)
  - [Prerequisite](#prerequisite)
    - [From Binary](#from-binary)
    - [From Source](#from-source)
- [Running nuclei](#running-nuclei)
    - [1. Running nuclei with single template](#1-running-nuclei-with-a-single-template)
    - [2. Running nuclei with multiple template](#2-running-nuclei-with-a-multiple-templates)
- [License](#license)

 # Features

<h1 align="left">
  <img src="static/nuclei-run.jpg" alt="nuclei" width="700px"></a>
  <br>
</h1>

 - Simple and modular code base making it easy to contribute.
 - Fast And fully configurable using a template based engine.
 - Handles edge cases doing retries, backoffs etc for handling WAFs.
 - Smart matching functionality for zero false positive scanning.

# Usage

```bash
nuclei -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag     | Description                                           | Example                    |
|----------|-------------------------------------------------------|----------------------------|
| -c       | Number of concurrent requests (default 10)            | nuclei -c 100              |
| -l       | List of urls to run templates                         | nuclei -l urls.txt         |
| -t       | Templates input file/files to check across hosts      | nuclei -t git-core.yaml    |
| -t       | Templates input file/files to check across hosts      | nuclei -t "path/*.yaml"    |
| -nC      | Don't Use colors in output                            | nuclei -nC                 |
| -o       | File to save output result (optional)                 | nuclei -o output.txt       |
| -silent  | Show only found results in output                     | nuclei -silent             |
| -retries | Number of times to retry a failed request (default 1) | nuclei -retries 1          |
| -timeout | Seconds to wait before timeout (default 5)            | nuclei -timeout 5          |
| -v       | Show Verbose output                                   | nuclei -v                  |
| -version | Show version of nuclei                                | nuclei -version            |


# Installation Instructions


### From Binary

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/projectdiscovery/nuclei/releases/) page. Extract them using tar, move it to your `$PATH`and you're ready to go.

```bash
> tar -xzvf nuclei-linux-amd64.tar
> mv nuclei-linux-amd64 /usr/bin/nuclei
> nuclei -h
```

### From Source

nuclei requires go1.13+ to install successfully. Run the following command to get the repo - 

```bash
> GO111MODULE=on go get -u -v github.com/projectdiscovery/nuclei/cmd/nuclei
```

In order to update the tool, you can use -u flag with `go get` command.

# Running nuclei

### 1. Running nuclei with a single template. 

This will run the tool against all the hosts in `urls.txt` and returns the matched results. 

```bash
> nuclei -l urls.txt -t git-core.yaml -o results.txt
```

You can also pass the list of hosts at standard input (STDIN). This allows for easy integration in automation pipelines.

This will run the tool against all the hosts in `urls.txt` and returns the matched results. 

```bash
> cat urls.txt | nuclei -t git-core.yaml -o results.txt
```

### 2. Running nuclei with multiple templates. 

This will run the tool against all the hosts in `urls.txt` with all the templates in the `path-to-templates` directory and returns the matched results. 

```bash
> nuclei -l urls.txt -t "path-to-templates/*.yaml" -o results.txt 
```

Nuclei supports glob expression ending in `.yaml` meaning multiple templates can be easily passed to be executed one after the other.


# Thanks

nuclei is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/nuclei/blob/master/THANKS.md)** file for more details.
