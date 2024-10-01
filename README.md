![nuclei](/static/nuclei-cover.png)

<p align="center">
	<h1 align="center"><b>Nuclei</b></h1>
</p>

<p align="center" >
 <img src="https://img.shields.io/badge/go-1.21-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white">
 &nbsp;&nbsp;
 <img src="https://shields.io/badge/Version-3.3.4-black?style=for-the-badge">
  &nbsp;&nbsp;
 <img src="https://img.shields.io/badge/downloads-2M-000000.svg?style=for-the-badge">
</p>

<p align="center" >
 <a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white"></a>
 &nbsp;&nbsp;
 <a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/badge/@pdiscoveryio-%23000000.svg?style=for-the-badge&logo=x&logoColor=white"></a>
</p>

<br />

## About Nuclei

Nuclei is a modern, high-performance vulnerability scanner that leverages simple YAML-based templates. It empowers you to design custom vulnerability detection scenarios that mimic real-world conditions, leading to accurate results with zero false positives.

- Simple YAML format for creating and customizing vulnerability templates.
- Actively contributed by thousands of security practitioners collaborating on current attack vectors.
- Reduce false positives by simulating real-world steps to verify vulnerabilities
- Ultra-fast parallel scan processing and request clustering.
- Integrate into CI/CD pipelines for vulnerability detection and regression testing.
- Supports multiple protocols like TCP, DNS, HTTP, SSL, WHOIS JavaScript, Code and more.
- Integrate with Jira, Splunk, GitHub, Elastic, GitLab and others to streamline vulnerability management

### Our Mission

Traditional vulnerability scanners were built decades ago. They are closed-source, incredibly slow, and vendor-driven. Today's attackers are mass exploiting newly released CVEs across the internet within days, unlike the years it used to take. This shift requires a completely different approach to tackling trending exploits on the internet.

We built Nuclei to solve this challenge. We made the entire scanning engine framework open and customizable—allowing the global security community to collaborate and tackle the trending attack vectors and vulnerabilities on the internet. Nuclei is now used by Fortune 500 enterprises, government agencies, universities and startups to defend exploitable vulnerabilities.

You can participate by contributing to our code, templates library, or joining our team.

<br />

## Get Started

**There are two ways to start using Nuclei:**

- [Install](https://github.com/projectdiscovery/nuclei?tab=readme-ov-file#Installation) Nuclei on your machine. See the installation guides here.
- [Sign up](https://cloud.projectdiscovery.io/sign-up) for cloud (50x faster than local).

<br />

**Start here:**

<table>
<tr>
<td>  
<p>
<a href="/#">Installation</a>
 &nbsp;&nbsp;·&nbsp;&nbsp;
 <a href="https://docs.projectdiscovery.io/tools/nuclei/">Documentation</a>
 &nbsp;&nbsp;·&nbsp;&nbsp;
 <a href="https://github.com/projectdiscovery/nuclei-templates">Templates Library</a>
 &nbsp;&nbsp;·&nbsp;&nbsp;
 <a href="https://docs.projectdiscovery.io/templates/">Templating Guide</a>
 &nbsp;&nbsp;·&nbsp;&nbsp;
 <a href="/#">Resources</a>
</p>
</td>
</tr>
</table>

<br />

## Installation

Nuclei requires **Go** `1.21` to install successfully. Run the following command to install the latest version -

```sh
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

<details>
  <summary>Brew</summary>
  
  ```sh
  brew install nuclei
  ```
  
</details>
<details>
  <summary>Docker</summary>
  
  ```sh
  docker pull projectdiscovery/nuclei:latest
  ```
  
</details>

<table>
<tr>
<td>  
More installation methods can be <a href="https://docs.projectdiscovery.io/tools/nuclei/install">found here</a>.
</td>
</tr>
</table>

<br /> 

## Usage Examples

Here are a few common ways to use Nuclei for scanning:

### Single Target Scans

To perform a quick scan on a web application for common vulnerabilities, you can run. This will check for vulnerabilities using Nuclei’s default templates.

```sh
nuclei -target https://example.com
```

### Scanning Multiple Targets

Nuclei can handle bulk scanning by providing a list of targets. You can use a file containing multiple URLs.

```sh
nuclei -targets urls.txt
```

### Running a Scan in Network Mode

If you need to scan an IP range for network vulnerabilities, you can run. This will scan the entire subnet for network-related issues, such as open ports or misconfigured services.

```sh
nuclei -target 192.168.1.0/24 -t network/
```

### Scanning with your Custom Template

To write and use your own template, create a `.yaml` file with specific rules, then use it as follows.

```sh
nuclei -u https://example.com -t /path/to/your-template.yaml
```

### Connect with PD Cloud Platform

You can run the scans on your machine and upload the results to the cloud platform for further analysis.

```sh
nuclei -target https://example.com -cloud-upload
```

> [!NOTE]
> This feature is absolutely free and does not require any subscription. For a detailed guide, refer to the [documentation](https://docs.projectdiscovery.io/cloud/scanning/nuclei-scan).

<br />

## Resources

- [Fuzzing with Nuclei](https://www.youtube.com/watch?v=9nK3ya4DW9w&ab_channel=BSidesLV), A talk by Brendan O’leary at BSides Las Vegas.
- [Finding bugs with Nuclei with PinkDraconian (Robbe Van Roey)](https://www.youtube.com/watch?v=ewP0xVPW-Pk) by @PinkDraconian.
- [Nuclei: Packing a Punch with Vulnerability Scanning](https://bishopfox.com/blog/nuclei-vulnerability-scan) by Bishopfox.
- [WAF framework measures WAF effectiveness | Fastly](https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf/) by Fastly.
- [CI/CD and Regressions with Nuclei](https://medium.com/@jhaveri_jeet/understanding-the-nuclei-tool-automating-security-vulnerability-detection-cdf277a13e0d) (Write up by Ben Howarth)

<table>
<tr>
<td>  
More resources can be found in the <a href="https://docs.projectdiscovery.io/tools/nuclei/resources">documentation</a>.
</td>
</tr>
</table>

<br />

## Credits

Thanks to all the amazing [community contributors for sending PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors) and keeping this project updated. :heart:

If you have an idea or some kind of improvement, you are welcome to contribute and participate in the Project, feel free to send your PR.

<p align="center">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=projectdiscovery/nuclei&max=500" >
</a>
</p>


Do also check out the below similar open-source projects that may fit in your workflow:

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

<br />

## License

Nuclei is distributed under [MIT License](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md).

<img src="https://img.shields.io/badge/license-MIT-000000.svg?style=for-the-badge">

<h1 align="left">
  <a href="https://discord.gg/projectdiscovery"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a>
  <a href="https://docs.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>