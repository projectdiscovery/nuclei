<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">Fast and customisable vulnerability scanner based on simple YAML based DSL.</h4>


<p align="center">
<a href="https://goreportcard.com/report/github.com/projectdiscovery/nuclei"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/nuclei"></a>
<a href="https://github.com/projectdiscovery/nuclei/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/projectdiscovery/nuclei/releases"><img src="https://img.shields.io/github/release/projectdiscovery/nuclei"></a>
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
<a href="https://discord.gg/KECAGdH"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
<a href="https://github.com/projectdiscovery/nuclei/actions/workflows/build-test.yml"><img src="https://github.com/projectdiscovery/nuclei/actions/workflows/build-test.yml/badge.svg?branch=master"></a>
</p>
      
<p align="center">
  <a href="#how-it-works">How</a> •
  <a href="#install-nuclei">Install</a> •
  <a href="#for-security-engineers">For Security Engineers</a> •
  <a href="#for-developers-and-organisations">For Developers</a> •
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/">Documentation</a> •
  <a href="#credits">Credits</a> •
  <a href="https://nuclei.projectdiscovery.io/faq/nuclei/">FAQs</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

---

Nuclei is used to send requests across targets based on a template leading to zero false positives and providing fast scanning on large number of hosts. Nuclei offers scanning for a variety of protocols including TCP, DNS, HTTP, File, etc. With powerful and flexible templating, all kinds of security checks can be modelled with Nuclei.

We have a [dedicated repository](https://github.com/projectdiscovery/nuclei-templates) that houses various type of vulnerability templates contributed by **more than 100** security researchers and engineers. It is preloaded with ready to use templates using `-update-templates` flag.



## How it works


<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>


# Install Nuclei

```sh
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```

**More installation [methods can be found here](https://nuclei.projectdiscovery.io/nuclei/get-started/).**

<table>
<tr>
<td>  

### Nuclei Templates

Nuclei has had built-in support for automatic update/download templates since version [v2.4.0](https://github.com/projectdiscovery/nuclei/releases/tag/v2.4.0). [**Nuclei-Templates**](https://github.com/projectdiscovery/nuclei-templates) project provides a community-contributed list of ready-to-use templates that is constantly updated.

You may still use the `update-templates` flag to update the nuclei templates at any time; automatic updates happen every 24 hours. You can write your own checks for your individual workflow and needs following Nuclei's [templating guide](https://nuclei.projectdiscovery.io/templating-guide/).

</td>
</tr>
</table>

### Usage

```sh
nuclei -h
```

This will display help for the tool. Here are all the switches it supports.

<details>
<summary> 👉 nuclei help menu 👈</summary>

```
Usage:
  nuclei [flags]

Flags:
   -H, -header value                  Custom Header.
   -author value                      Templates to run based on author
   -bs, -bulk-size int                Maximum Number of hosts analyzed in parallel per template (default 25)
   -c, -concurrency int               Maximum Number of templates executed in parallel (default 10)
   -config string                     Nuclei configuration file
   -debug                             Debugging request and responses
   -debug-req                         Debugging request
   -debug-resp                        Debugging response
   -et, -exclude value                Templates to exclude, supports single and multiple templates using directory.
   -etags, -exclude-tags value        Exclude templates with the provided tags
   -headless                          Enable headless browser based templates support
   -impact, -severity value           Templates to run based on severity
   -irr, -include-rr                  Write requests/responses for matches in JSON output
   -include-tags value                Tags to force run even if they are in denylist
   -include-templates value           Templates to force run even if they are in denylist
   -interactions-cache-size int       Number of requests to keep in interactions cache (default 5000)
   -interactions-cooldown-period int  Extra time for interaction polling before exiting (default 5)
   -interactions-eviction int         Number of seconds to wait before evicting requests from cache (default 60)
   -interactions-poll-duration int    Number of seconds before each interaction poll request (default 5)
   -interactsh-url string             Self Hosted Interactsh Server URL (default https://interact.sh)
   -json                              Write json output to files
   -l, -list string                   List of URLs to run templates on
   -me, -markdown-export string       Directory to export results in markdown format
   -metrics                           Expose nuclei metrics on a port
   -metrics-port int                  Port to expose nuclei metrics on (default 9092)
   -nc, -no-color                     Disable colors in output
   -nt, -new-templates                Only run newly added templates
   -nm, -no-meta                      Don't display metadata for the matches
   -no-interactsh                     Do not use interactsh server for blind interaction polling
   -o, -output string                 File to write output to (optional)
   -page-timeout int                  Seconds to wait for each page in headless (default 20)
   -passive                           Enable Passive HTTP response processing mode
   -project                           Use a project folder to avoid sending same request multiple times
   -project-path string               Use a user defined project folder, temporary folder is used if not specified but enabled
   -proxy-socks-url string            URL of the proxy socks server
   -proxy-url string                  URL of the proxy server
   -r, -resolvers string              File containing resolver list for nuclei
   -rl, -rate-limit int               Maximum requests to send per second (default 150)
   -rc, -report-config string         Nuclei Reporting Module configuration file
   -rdb, -report-db string            Local Nuclei Reporting Database (Always use this to persistent report data)
   -retries int                       Number of times to retry a failed request (default 1)
   -se, -sarif-export string          File to export results in sarif format
   -show-browser                      Show the browser on the screen
   -si, -stats-interval int           Number of seconds between each stats line (default 5)
   -silent                            Show only results in output
   -spm, -stop-at-first-path          Stop processing http requests at first match (this may break template/workflow logic)
   -stats                             Display stats of the running scan
   -stats-json                        Write stats output in JSON format
   -system-resolvers                  Use system dns resolving as error fallback
   -t, -templates value               Templates to run, supports single and multiple templates using directory.
   -tags value                        Tags to execute templates for
   -u, -target string                 URL to scan with nuclei
   -tv, -templates-version            Shows the installed nuclei-templates version
   -timeout int                       Time to wait in seconds before timeout (default 5)
   -tl                                List available templates
   -trace-log string                  File to write sent requests trace log
   -ud, -update-directory string      Directory storing nuclei-templates (default /Users/geekboy/nuclei-templates)
   -ut, -update-templates             Download / updates nuclei community templates
   -v, -verbose                       Show verbose output
   -validate                          Validate the passed templates to nuclei
   -version                           Show version of nuclei
   -vv                                Display Extra Verbose Information
   -w, -workflows value               Workflows to run for nuclei
```

</details>

### Running Nuclei

Scanning target URLs with [community-curated](https://github.com/projectdiscovery/nuclei-templates) nuclei templates.

```sh
nuclei -list urls.txt
```

Example of `urls.txt`:

```yaml
https://redacted.com
https://test.redacted.com
http://example.com
http://app.example.com
```

**More detailed examples of running nuclei can be found [here](https://nuclei.projectdiscovery.io/nuclei/get-started/#running-nuclei).**

# For Security Engineers

Nuclei offers great number of features that are helpful for security engineers to customise workflow in their organisation. With the varieties of scan capabilities (like DNS, HTTP, TCP), security engineers can easily create their suite of custom checks with Nuclei.

- Varieties of protocols supported: TCP, DNS, HTTP, File, etc
- Achieve complex vulnerability steps with workflows and [dynamic requests.](https://blog.projectdiscovery.io/nuclei-unleashed-quickly-write-complex-exploits/)
- Easy to integrate into CI/CD, designed to be easily integrated into regression cycle to actively check the fix and re-appearance of vulnerability. 

<h1 align="left">
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

<table>
<tr>
<td>  

**For bugbounty hunters:**

Nuclei allows you to customise your testing approach with your own suite of checks and easily run across your bug bounty programs. Moreover, Nuclei can be easily integrated into any continuous scanning workflow.

- Designed to be easily integrated into other tool workflow.
- Can process thousands of hosts in few minutes.
- Easily automate your custom testing approach with our simple YAML DSL.

Please check our other open-source projects that might fit into your bug bounty workflow: [github.com/projectdiscovery](http://github.com/projectdiscovery), we also host daily [refresh of DNS data at Chaos](http://chaos.projectdiscovery.io).

</td>
</tr>
</table>

<table>
<tr>
<td>
  
**For pentesters:**

Nuclei immensely improve how you approach security assessment by augmenting the manual repetitve processes. Consultancies are already converting their manual assessment steps with Nuclei, it allows them to run set of their custom assessment approach across thousands of hosts in an automated manner. 

Pen-testers get the full power of our public templates and customization capabilities to speed-up their assessment process, and specifically with the regression cycle where you can easily verify the fix.

- Easily create your compliance, standards suite (e.g. OWASP Top 10) checklist.
- With capabilities like [fuzz](https://nuclei.projectdiscovery.io/templating-guide/#advance-fuzzing) and [workflows](https://nuclei.projectdiscovery.io/templating-guide/#workflows), complex manual steps and repetitive assessment can be easily automated with Nuclei.
- Easy to re-test vulnerability-fix by just re-running the template.

</td>
</tr>
</table>


# For Developers and Organisations

Nuclei is built with simplicity in mind, with the community backed templates by hundreds of security researchers, it allows you to stay updated with latest security threats using continuous Nuclei scanning on the hosts. It is designed to be easily integrated into regression tests cycle, to verify the fixes and  eliminate vulnerabilities from occuring in future.

- **CI/CD:** Engineers are already utilising Nuclei within their CI/CD pipeline, it allows them to constantly monitor their staging and production environments with customised templates.
- **Continuous Regression Cycle:** With Nuclei, you can create your custom template on every new identified vulnerability and put into Nuclei engine to eliminate in the continuous regression cycle.

We have [a discussion thread around this](https://github.com/projectdiscovery/nuclei-templates/discussions/693), there are already some bug bounty programs giving incentives to hackers on writing nuclei templates with every submission, that helps them to eliminate the vulnerability across all their assets, as well as to eliminate future risk in reappearing on productions. If you're interested in implementing it in your organisation, feel free to [reach out to us](mailto:contact@projectdiscovery.io). We will be more than happy to help you in the getting started process, or you can also post into the [discussion thread for any help](https://github.com/projectdiscovery/nuclei-templates/discussions/693).

<h3 align="center">
  <img src="static/regression-with-nuclei.jpg" alt="regression-cycle-with-nuclei" width="1100px"></a>
</h3>

<h1 align="left">
  <a href="https://github.com/projectdiscovery/nuclei-action"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

### Resources

- [Community Powered Scanning with Nuclei](https://blog.projectdiscovery.io/community-powered-scanning-with-nuclei/)
- [Nuclei Unleashed - Quickly write complex exploits](https://blog.projectdiscovery.io/nuclei-unleashed-quickly-write-complex-exploits/)
- [Nuclei - Fuzz all the things](https://blog.projectdiscovery.io/nuclei-fuzz-all-the-things/)
- [Weaponizes nuclei Workflows to Pwn All the Things](https://medium.com/@dwisiswant0/weaponizes-nuclei-workflows-to-pwn-all-the-things-cd01223feb77) by [@dwisiswant0](https://github.com/dwisiswant0)
- [How to Scan Continuously with Nuclei?](https://medium.com/@dwisiswant0/how-to-scan-continuously-with-nuclei-fcb7e9d8b8b9) by [@dwisiswant0](https://github.com/dwisiswant0)

### Credits

Thanks to all the amazing community [contributors for sending PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors). Do also check out the below similar open-source projects that may fit in your workflow:

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### License

Nuclei is distributed under [MIT License](https://github.com/projectdiscovery/nuclei/blob/master/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/KECAGdH"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://nuclei.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>
