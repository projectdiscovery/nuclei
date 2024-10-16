![nuclei](/static/nuclei-cover-image.png)

<p align="center">
  <strong>Nuclei</strong> by ProjectDiscovery
</p>

<p align="center">

<img src="https://img.shields.io/badge/go-1.21-%2300ADD8.svg?style=for-the-badge&logo=go&logoColor=white">
&nbsp;&nbsp;
<a href="https://docs.projectdiscovery.io/tools/nuclei/overview"><img src="https://img.shields.io/badge/Documentation-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIiBjbGFzcz0ibHVjaWRlIGx1Y2lkZS1ib29rLW9wZW4iPjxwYXRoIGQ9Ik0xMiA3djE0Ii8+PHBhdGggZD0iTTMgMThhMSAxIDAgMCAxLTEtMVY0YTEgMSAwIDAgMSAxLTFoNWE0IDQgMCAwIDEgNCA0IDQgNCAwIDAgMSA0LTRoNWExIDEgMCAwIDEgMSAxdjEzYTEgMSAwIDAgMS0xIDFoLTZhMyAzIDAgMCAwLTMgMyAzIDMgMCAwIDAtMy0zeiIvPjwvc3ZnPg==&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://docs.projectdiscovery.io/tools/nuclei/overview"><img src="https://img.shields.io/badge/Templates Library-%23000000.svg?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IiNmZmZmZmYiIHN0cm9rZS13aWR0aD0iMS41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiIGNsYXNzPSJsdWNpZGUgbHVjaWRlLXNoaWVsZCI+PHBhdGggZD0iTTIwIDEzYzAgNS0zLjUgNy41LTcuNjYgOC45NWExIDEgMCAwIDEtLjY3LS4wMUM3LjUgMjAuNSA0IDE4IDQgMTNWNmExIDEgMCAwIDEgMS0xYzIgMCA0LjUtMS4yIDYuMjQtMi43MmExLjE3IDEuMTcgMCAwIDEgMS41MiAwQzE0LjUxIDMuODEgMTcgNSAxOSA1YTEgMSAwIDAgMSAxIDF6Ii8+PC9zdmc+&logoColor=white"></a>
&nbsp;&nbsp;
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white"></a>

----


</p>
	
<br />

Nuclei is a modern, high-performance vulnerability scanner that leverages simple YAML-based templates. It empowers you to design custom vulnerability detection scenarios that mimic real-world conditions, leading to zero false positives.

- Simple YAML format for creating and customizing vulnerability templates.
- Contributed by thousands of security professionals to tackle trending vulnerabilities.
- Reduce false positives by simulating real-world steps to verify a vulnerability.
- Ultra-fast parallel scan processing and request clustering.
- Integrate into CI/CD pipelines for vulnerability detection and regression testing.
- Supports multiple protocols like TCP, DNS, HTTP, SSL, WHOIS JavaScript, Code and more.
- Integrate with Jira, Splunk, GitHub, Elastic, GitLab.

## Get Started

Nuclei offers two ways to begin your vulnerability scanning journey:

### **1. Nuclei CLI - Free**

Install Nuclei on your Command Line Interface (CLI) for free. Get started by following the installation guide [here](https://docs.projectdiscovery.io/tools/nuclei/install). Enhance your experience by connecting to our cloud platform to:

- Ideal for: Bug bounty hunters, researchers, and individuals
- Visualize your vulnerability findings
- Write and manage your detections templates
- Browse the latest trending vulnerabilities

### **2. ProjectDiscovery Pro and Enterprise**

Upgrade to [ProjectDiscovery Pro](https://projectdiscovery.io/pricing) for the fastest and most reliable scanning:

- **Ideal for:** Pentesters, security teams, and enterprises
- **50x Faster Scans**
- **Large-scale Scanning**
- **Ticketing and Notification Integrations**
- **Comprehensive Reporting & Analytics**
- **Plus:** Real-time scanning, SAML SSO, SOC 2 compliance, shared team workspaces, and more

👉 [**Sign Up Now**](https://projectdiscovery.io/pricing) to unlock the full potential of Nuclei with our Pro and Enterprise editions.


## Learn more

Here are a few common ways to use Nuclei for scanning:

### Single target scan

To perform a quick scan on web-application:

```sh
nuclei -target https://example.com
```

### Scanning multiple targets

Nuclei can handle bulk scanning by providing a list of targets. You can use a file containing multiple URLs.

```sh
nuclei -targets urls.txt
```

### Network scan
If you need to scan an IP range for network vulnerabilities, you can run. This will scan the entire subnet for network-related issues, such as open ports or misconfigured services.

```sh
nuclei -target 192.168.1.0/24 -t network/
```

### Scanning with your custom template

To write and use your own template, create a `.yaml` file with specific rules, then use it as follows.

```sh
nuclei -u https://example.com -t /path/to/your-template.yaml
```

### Connect with ProjectDiscovery Cloud Platform

You can run the scans on your machine and upload the results to the cloud platform for further analysis.

```sh
nuclei -target https://example.com -cloud-upload
```

> [!NOTE]
> This feature is absolutely free and does not require any subscription. For a detailed guide, refer to the [documentation](https://docs.projectdiscovery.io/cloud/scanning/nuclei-scan).

<br />

### Our Mission

Traditional vulnerability scanners were built decades ago. They are closed-source, incredibly slow, and vendor-driven. Today's attackers are mass exploiting newly released CVEs across the internet within days, unlike the years it used to take. This shift requires a completely different approach to tackling trending exploits on the internet.

We built Nuclei to solve this challenge. We made the entire scanning engine framework open and customizable—allowing the global security community to collaborate and tackle the trending attack vectors and vulnerabilities on the internet. Nuclei is now used and contributed by Fortune 500 enterprises, government agencies, universities.

You can participate by contributing to our code, templates library, or joining our team.

<br />

## Contributors :heart:

Thanks to all the amazing [community contributors for sending PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors) and keeping this project updated. :heart:

<p align="left">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=projectdiscovery/nuclei&max=300" >
</a>
</p>


## License

Nuclei is distributed under [MIT License](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md).

<img src="https://img.shields.io/badge/license-MIT-000000.svg?style=for-the-badge">
