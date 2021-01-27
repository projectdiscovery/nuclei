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

🎯 Resources
----

-   [Features](#features)
-   [Installation Instructions](#installation-instructions)
-   [Nuclei templates](#nuclei-templates)
-   [Usage](#usage)
-   [Running nuclei](#running-nuclei)
-   [Rate Limits](#rate-limits)
-   [Template exclusion](#template-exclusion)
-   [Acknowledgments](#acknowledgments)


✅ Features
----

<h1 align="left">
  <img src="static/nuclei-run.png" alt="nuclei" width="700px"></a>
  <br>
</h1>

-   Fast And fully configurable using a template based engine.
-   Simple and modular code base making it easy to contribute.
-   Handles edge cases doing retries, backoffs etc for handling WAFs.
-   Smart matching functionality for zero false positive scanning.


📖 Nuclei Templates
-----

Please navigate to https://nuclei.projectdiscovery.io for detailed documentation to **build** new and your **own custom** templates, we have also added many example templates for easy understanding.

💪 Contributions
-----

Nuclei is powered by major contributions of templates from the community. [Template contributions ](https://github.com/projectdiscovery/nuclei-templates/issues/new?assignees=&labels=&template=submit-template.md&title=%5Bnuclei-template%5D+), [Feature Requests](https://github.com/projectdiscovery/nuclei/issues/new?assignees=&labels=&template=feature_request.md&title=%5Bfeature%5D) and [Bug Reports](https://github.com/projectdiscovery/nuclei/issues/new?assignees=&labels=&template=bug_report.md&title=%5BBug%5D+) are more than welcome.

💬 Discussion
-----

Have questions / doubts / ideas to discuss? feel free to open a discussion using [Github discussions](https://github.com/projectdiscovery/nuclei/discussions) board.

👨‍💻 Community
-----

You are welcomed to join our [Discord Community](https://discord.gg/KECAGdH). You can also follow us on [Twitter](https://twitter.com/pdnuclei) to keep up with everything related to Nuclei project.

⚠️ Notes
-----

- Progress bar (stats) is experimental feature, might not work in all cases.
- Progress bar (stats) has known issues with workflows.

📣 Acknowledgments
----

Please also check out similar awesome projects that may fit in your workflow:

[Burp Suite](https://portswigger.net/burp), [FFuF](https://github.com/ffuf/ffuf), [Jaeles](https://github.com/jaeles-project/jaeles), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [ChopChop](https://github.com/michelin/ChopChop)


📌 Resources
-----

- [Automate Security Regression Testing With Nuclei](https://handsonappsec.medium.com/automate-security-regression-testing-featuring-nuclei-204b6970be7a) by [@toufik-airane](https://github.com/toufik-airane)
- [Build A Cloud-Native Application Security Operations Center](https://handsonappsec.medium.com/build-a-cloud-native-application-security-operations-center-3b4100ea1a79) by [@toufik-airane](https://github.com/toufik-airane)
- [Weaponizes nuclei Workflows to Pwn All the Things](https://medium.com/@dwi.siswanto98/weaponizes-nuclei-workflows-to-pwn-all-the-things-cd01223feb77) by [@toufik-airane](https://github.com/dwisiswant0)
- [How to Scan Continuously with Nuclei?](https://medium.com/@dwi.siswanto98/how-to-scan-continuously-with-nuclei-fcb7e9d8b8b9) by [@toufik-airane](https://github.com/dwisiswant0)

📄 License
----

Nuclei is licensed under [MIT](https://github.com/projectdiscovery/nuclei/blob/master/LICENSE.md) Open Source license and is available for free.

--------

Nuclei is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/nuclei/blob/master/THANKS.md)** file for more details.
