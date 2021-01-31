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
</p>
      
<p align="center">
  <a href="#how-it-works">How</a> •
  <a href="#install-nuclei">Install</a> •
  <a href="#for-security-engineers">For Security Engineers</a> •
  <a href="#for-developers-and-organisations">For Developers</a> •
  <a href="https://nuclei.projectdiscovery.io">Wiki</a> •
  <a href="#credits">Credits</a> •
  <a href="#license">License</a> •
  <a href="https://discord.gg/KECAGdH">Join Discord</a>
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
▶ GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
```
**More installation [methods can be found here](https://nuclei.projectdiscovery.io/nuclei/get-started/).**

<table>
<tr>
<td>  

### Download Templates

You can download and update the nuclei templates using <ins>*update-templates*</ins> flag of nuclei that downloads all the available **nuclei-templates** from [Github project](https://github.com/projectdiscovery/nuclei-templates), a community curated list of templates that are ready to use.

`▶ nuclei -update-templates`

Nuclei is designed to used with custom templates according to the target and workflow, you can write your own checks for your specific workflow and needs, please refer to nuclei **[templating guide](https://nuclei.projectdiscovery.io/templating-guide/)** to write your own custom templates.

</td>
</tr>
</table>

### Running Nuclei

Scanning for CVEs on given list of URLs.

```sh
▶ nuclei -l target_urls.txt -t cves/
```

**More detailed examples of running nuclei can be found [here](https://nuclei.projectdiscovery.io/nuclei/get-started/#using-nuclei).**

# For Security Engineers

Nuclei offers great number of features that are helpful for security engineers to customise workflow in their organisation. With the varieties of scan capabilities (like DNS, HTTP, TCP), security engineers can easily create their suite of custom checks with Nuclei.

- Varieties of protocols supported: TCP, DNS, HTTP, File, etc
- Achieve complex vulnerability steps with workflows and [dynamic requests.](https://blog.projectdiscovery.io/post/nuclei-unleashed/)
- [Easy to integrate into CI/CD](https://handsonappsec.medium.com/build-a-cloud-native-application-security-operations-center-3b4100ea1a79), designed to be easily integrated into regression cycle to actively check the fix and re-appearance of vulnerability. 

<h1 align="left">
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

<table>
<tr>
<td>  

**For bugbounty hunters:**

Nuclei allows you to customise your testing approach with your own suite of checks and easily run across your bug bounty programs. Moroever, Nuclei can be easily integrated into any continuous scanning workflow.

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

- **CI/CD:** Engineers are already [utilising Nuclei within their CI/CD pipeline](https://handsonappsec.medium.com/build-a-cloud-native-application-security-operations-center-3b4100ea1a79), it allows them to constantly monitor their staging and production environments with customised templates.
- **Continuous Regression Cycle:** With Nuclei, you can create your custom template on every new identified vulnerability and put into Nuclei engine to eliminate in the continuous regression cycle.

We have [a discussion thread around this](https://github.com/projectdiscovery/nuclei-templates/discussions/693), there are already some bug bounty programs giving incentives to hackers on writing nuclei templates with every submission, that helps them to eliminate the vulnerability across all their assets, as well as to eliminate future risk in reappearing on productions. If you're interested in implementing it in your organisation, feel free to [reach out to us](mailto:contact@projectdiscovery.io). We will be more than happy to help you in the getting started process, or you can also post into the [discussion thread for any help](https://github.com/projectdiscovery/nuclei-templates/discussions/693).

<h3 align="center">
  <img src="static/regression-with-nuclei.jpg" alt="regression-cycle-with-nuclei" width="1100px"></a>
</h3>

<h1 align="left">
  <a href="https://github.com/projectdiscovery/nuclei-action"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

### Resources


- [Community Powered Scanning with Nuclei](https://blog.projectdiscovery.io/post/nuclei-introduction/)
- [Nuclei Unleashed - Quickly write complex exploits](https://blog.projectdiscovery.io/post/nuclei-unleashed/)
- [Nuclei - Fuzz all the things](https://blog.projectdiscovery.io/post/nuclei-fuzz-all-the-things/)
- [Automate Security Regression Testing With Nuclei](https://handsonappsec.medium.com/automate-security-regression-testing-featuring-nuclei-204b6970be7a) by [@toufik-airane](https://github.com/toufik-airane)
- [Build A Cloud-Native Application Security Operations Center](https://handsonappsec.medium.com/build-a-cloud-native-application-security-operations-center-3b4100ea1a79) by [@toufik-airane](https://github.com/toufik-airane)
- [Weaponizes nuclei Workflows to Pwn All the Things](https://medium.com/@dwi.siswanto98/weaponizes-nuclei-workflows-to-pwn-all-the-things-cd01223feb77) by [@dwisiswant0](https://github.com/dwisiswant0)
- [How to Scan Continuously with Nuclei?](https://medium.com/@dwi.siswanto98/how-to-scan-continuously-with-nuclei-fcb7e9d8b8b9) by [@dwisiswant0](https://github.com/dwisiswant0)


### Credits

Thanks to all the amazing community [contributors for sending PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors). Do also check out the below similar open-source projects that may fit in your workflow:

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### License

Nuclei is distributed under [MIT License](https://github.com/projectdiscovery/nuclei/blob/master/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/KECAGdH"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://nuclei.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>
