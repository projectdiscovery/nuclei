<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">DSL 기반의 간단한 YAML을 기초로한 빠른 맞춤형 취약점 스캐너</h4>

<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/projectdiscovery/nuclei?filename=v2%2Fgo.mod">
<a href="https://github.com/projectdiscovery/nuclei/releases"><img src="https://img.shields.io/github/downloads/projectdiscovery/nuclei/total">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases/"><img src="https://img.shields.io/github/release/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/issues"><img src="https://img.shields.io/github/issues-raw/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/discussions"><img src="https://img.shields.io/github/discussions/projectdiscovery/nuclei">
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
</p>
      
<p align="center">
  <a href="#작동-방식">작동 방식</a> •
  <a href="#설치">설치</a> •
  <a href="#보안-엔지니어를-위한">보안 엔지니어를 위한</a> •
  <a href="#개발자를-위한">개발자를 위한</a> •
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/">문서</a> •
  <a href="#credits">Credits</a> •
  <a href="https://nuclei.projectdiscovery.io/faq/nuclei/">FAQs</a> •
  <a href="https://discord.gg/projectdiscovery"> Discord 참가</a>
</p>

<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei/blob/master/README.md">English</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/master/README_CN.md">中文</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/master/README_KR.md">한국어</a>
</p>

---

Nuclei는 템플릿을 기반으로 대상 간에 요청을 보내기 위해 사용되며 긍정 오류(false positives)가 0이고 다수의 호스트에서 빠른 스캔을 제공합니다. Nuclei는 TCP, DNS, HTTP, SSL, File, Whois, Websocket, Headless 등을 포함한 다양한 프로토콜의 스캔을 제공합니다. 강력하고 유연한 템플릿을 통해 Nuclei는 모든 종류의 보안 검사를 모델링 할 수 있습니다.

**300명 이상의** 보안 연구원과 엔지니어가 제공한 다양한 유형의 취약점 템플릿을 보관하는 [전용 저장소](https://github.com/projectdiscovery/nuclei-templates)를 보유하고 있습니다.



## 작동 방식

<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>


# 설치

Nuclei를 성공적으로 설치하기 위해서 **go1.17**가 필요합니다. 다음 명령을 실행하여 최신 버전을 설치합니다.

```sh
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

**자세한 설치 방법은 [여기에서 찾을 수 있습니다.](https://nuclei.projectdiscovery.io/nuclei/get-started/).**

<table>
<tr>
<td>  

### Nuclei 템플릿

Nuclei는 [v2.5.2](https://github.com/projectdiscovery/nuclei/releases/tag/v2.5.2)부터 자동 템플릿 다운로드/업데이트를 기본으로 지원합니다.
[**Nuclei-Templates**](https://github.com/projectdiscovery/nuclei-templates) 프로젝트는 지속적으로 업데이트되는 즉시 사용 가능한 템플릿 목록을 제공합니다.

`update-templates` 플래그를 사용하여 언제든 템플릿을 업데이트할 수 있습니다. Nuclei의 [템플릿 가이드](https://nuclei.projectdiscovery.io/templating-guide/)에 따라 개별 워크플로 및 요구 사항에 대한 자체 검사를 작성할 수 있습니다.

YAML DSL의 참조 구문은 [여기](SYNTAX-REFERENCE.md)에서 확인할 수 있습니다.

</td>
</tr>
</table>

### 사용 방법

```sh
nuclei -h
```

도구에 대한 도움말이 표시됩니다. 다음은 지원하는 모든 스위치들입니다.


```console
Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.

Usage:
  nuclei [flags]

Flags:
TARGET:
   -u, -target string[]  스캔할 URLs/hosts 대상
   -l, -list string      스캔할 URLs/hosts 대상 목록이 포함된 파일 경로(줄당 하나씩)
   -resume string        resume.cfg를 사용한 스캔 재개(클러스터링이 비활성화됨)

TEMPLATES:
   -nt, -new-templates          nuclei-templates에 가장 최근에 추가된 새 템플릿만 실행
   -as, -automatic-scan         태그 매핑에 대한 wappalyzer 기술 탐지를 사용한 자동 웹 스캔
   -t, -templates string[]      실행할 템플릿 또는 템플릿 디렉토리 목록(쉼표로 구분된 파일)
   -tu, -template-url string[]  실행할 템플릿 URL 목록(쉼표로 구분된 파일)
   -w, -workflows string[]      실행할 워크플로 또는 워크플로 디렉토리 목록(쉼표로 구분된 파일)
   -wu, -workflow-url string[]  실행할 워크플로 URL 목록(쉼표로 구분된 파일)
   -validate                    nuclei로 전달된 템플릿 검증
   -tl                          사용 가능한 모든 템플릿 목록

FILTERING:
   -a, -author string[]              작성자를 기준으로 실행할 템플릿(쉼표로 구분된 파일)
   -tags string[]                    태그를 기준으로 실행할 템플릿(쉼표로 구분된 파일)
   -etags, -exclude-tags string[]    태그를 기준으로 제외할 템플릿(쉼표로 구분된 파일)
   -itags, -include-tags string[]    태그가 기본 또는 구성에 의해 제외된 경우에도 실행됨
   -id, -template-id string[]        템플릿 ID들을 기준으로 실행할 템플릿(쉼표로 구분된 파일)
   -eid, -exclude-id string[]        템플릿 ID들을 기준으로 제외할 템플릿(쉼표로 구분된 파일)
   -it, -include-templates string[]  템플릿이 기본 또는 구성에 의해 제외된 경우에도 실행됨
   -et, -exclude-templates string[]  제외할 템플릿 또는 템플릿 디렉토리(파일로 구분됨, 파일)
   -s, -severity value[]             심각도를 기준으로 실행할 템플릿. 가능한 값: info, low, medium, high, critical, unknown
   -es, -exclude-severity value[]    심각도를 기준으로 제외할 템플릿. 가능한 값: info, low, medium, high, critical, unknown
   -pt, -type value[]                프로토콜 유형을 기준으로 실행할 템플릿. 가능한 값: dns, file, http, headless, network, workflow, ssl, websocket, whois
   -ept, -exclude-type value[]       프로토콜 유형에 따라 제외할 템플릿. 가능한 값: dns, file, http, headless, network, workflow, ssl, websocket, whois

OUTPUT:
   -o, -output string            발견된 문제/취약점를 쓰기 위한 출력 파일
   -sresp, -store-resp           nuclei을 통해 전달된 모든 요청/응답을 출력 디렉토리에 저장
   -srd, -store-resp-dir string  nuclei을 통해 전달된 모든 요청/응답을 사용자 지정 디렉토리에 저장(기본 "output")
   -silent                       결과만 표시
   -nc, -no-color                출력 내용 색상 비활성화 (ANSI escape codes)
   -json                         JSONL(ines) 형식으로 출력
   -irr, -include-rr             JSONL 출력에 요청/응답 쌍 포함(결과만)
   -nm, -no-meta                 cli 출력에서 결과 메타데이터 출력 비활성화
   -nts, -no-timestamp           cli 출력에서 결과 타임스탬프 출력 비활성화
   -rdb, -report-db string       nuclei 보고 데이터베이스(보고서 데이터를 유지하려면 항상 이것을 사용)
   -ms, -matcher-status          매치 실패 상태 표시
   -me, -markdown-export string  마크다운 형식으로 결과를 내보낼 디렉토리
   -se, -sarif-export string     결과를 SARIF 형식으로 내보내는 파일

CONFIGURATIONS:
   -config string              path to the nuclei configuration file
   -fr, -follow-redirects      enable following redirects for http templates
   -mr, -max-redirects int     max number of redirects to follow for http templates (default 10)
   -dr, -disable-redirects     disable redirects for http templates
   -rc, -report-config string  nuclei reporting module configuration file
   -H, -header string[]        custom header/cookie to include in all http request in header:value format (cli, file)
   -V, -var value              custom vars in key=value format
   -r, -resolvers string       file containing resolver list for nuclei
   -sr, -system-resolvers      use system DNS resolving as error fallback
   -passive                    enable passive HTTP response processing mode
   -ev, -env-vars              enable environment variables to be used in template
   -cc, -client-cert string    client certificate file (PEM-encoded) used for authenticating against scanned hosts
   -ck, -client-key string     client key file (PEM-encoded) used for authenticating against scanned hosts
   -ca, -client-ca string      client certificate authority file (PEM-encoded) used for authenticating against scanned hosts
   -sml, -show-match-line      show match lines for file templates, works with extractors only
   -ztls                       use ztls library with autofallback to standard one for tls13
   -sni string                 tls sni hostname to use (default: input domain name)

INTERACTSH:
   -iserver, -interactsh-server string  interactsh server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    authentication token for self-hosted interactsh server
   -interactions-cache-size int         number of requests to keep in the interactions cache (default 5000)
   -interactions-eviction int           number of seconds to wait before evicting requests from cache (default 60)
   -interactions-poll-duration int      number of seconds to wait before each interaction poll request (default 5)
   -interactions-cooldown-period int    extra time for interaction polling before exiting (default 5)
   -ni, -no-interactsh                  disable interactsh server for OAST testing, exclude OAST based templates

RATE-LIMIT:
   -rl, -rate-limit int            maximum number of requests to send per second (default 150)
   -rlm, -rate-limit-minute int    maximum number of requests to send per minute
   -bs, -bulk-size int             maximum number of hosts to be analyzed in parallel per template (default 25)
   -c, -concurrency int            maximum number of templates to be executed in parallel (default 25)
   -hbs, -headless-bulk-size int   maximum number of headless hosts to be analyzed in parallel per template (default 10)
   -hc, -headless-concurrency int  maximum number of headless templates to be executed in parallel (default 10)

OPTIMIZATIONS:
   -timeout int                time to wait in seconds before timeout (default 5)
   -retries int                number of times to retry a failed request (default 1)
   -ldp, -leave-default-ports  leave default HTTP/HTTPS ports (eg. host:80,host:443
   -mhe, -max-host-error int   max errors for a host before skipping from scan (default 30)
   -project                    use a project folder to avoid sending same request multiple times
   -project-path string        set a specific project path
   -spm, -stop-at-first-path   stop processing HTTP requests after the first match (may break template/workflow logic)
   -stream                     stream mode - start elaborating without sorting the input

HEADLESS:
   -headless            enable templates that require headless browser support (root user on linux will disable sandbox)
   -page-timeout int    seconds to wait for each page in headless mode (default 20)
   -sb, -show-browser   show the browser on the screen when running templates with headless mode
   -sc, -system-chrome  Use local installed chrome browser instead of nuclei installed

DEBUG:
   -debug                    show all requests and responses
   -dreq, -debug-req         show all sent requests
   -dresp, -debug-resp       show all received responses
   -p, -proxy string[]       list of http/socks5 proxy to use (comma separated or file input)
   -pi, -proxy-internal      proxy all internal requests
   -tlog, -trace-log string  file to write sent requests trace log
   -elog, -error-log string  file to write sent requests error log
   -version                  show nuclei version
   -hm, -hang-monitor        enable nuclei hang monitoring
   -v, -verbose              show verbose output
   -vv                       display templates loaded for scan
   -ep, -enable-pprof        enable pprof debugging server
   -tv, -templates-version   shows the version of the installed nuclei-templates

UPDATE:
   -update                        update nuclei engine to the latest released version
   -ut, -update-templates         update nuclei-templates to latest released version
   -ud, -update-directory string  overwrite the default directory to install nuclei-templates
   -duc, -disable-update-check    disable automatic nuclei/templates update check

STATISTICS:
   -stats                    display statistics about the running scan
   -sj, -stats-json          write statistics data to an output file in JSONL(ines) format
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)
   -m, -metrics              expose nuclei metrics on a port
   -mp, -metrics-port int    port to expose nuclei metrics on (default 9092)
```

### Running Nuclei

Scanning target domain with [community-curated](https://github.com/projectdiscovery/nuclei-templates) nuclei templates.

```sh
nuclei -u https://example.com
```

Scanning target URLs with [community-curated](https://github.com/projectdiscovery/nuclei-templates) nuclei templates.

```sh
nuclei -list urls.txt
```

Example of `urls.txt`:

```yaml
http://example.com
http://app.example.com
http://test.example.com
http://uat.example.com
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

**For Bug Bounty hunters:**

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
  
**For Penetration Testers:**

Nuclei immensely improve how you approach security assessment by augmenting the manual, repetitive processes. Consultancies are already converting their manual assessment steps with Nuclei, it allows them to run set of their custom assessment approach across thousands of hosts in an automated manner. 

Pen-testers get the full power of our public templates and customization capabilities to speed up their assessment process, and specifically with the regression cycle where you can easily verify the fix.

- Easily create your compliance, standards suite (e.g. OWASP Top 10) checklist.
- With capabilities like [fuzz](https://nuclei.projectdiscovery.io/templating-guide/#advance-fuzzing) and [workflows](https://nuclei.projectdiscovery.io/templating-guide/#workflows), complex manual steps and repetitive assessment can be easily automated with Nuclei.
- Easy to re-test vulnerability-fix by just re-running the template.

</td>
</tr>
</table>


# For Developers and Organisations

Nuclei is built with simplicity in mind, with the community backed templates by hundreds of security researchers, it allows you to stay updated with the latest security threats using continuous Nuclei scanning on the hosts. It is designed to be easily integrated into regression tests cycle, to verify the fixes and eliminate vulnerabilities from occurring in the future.

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

- [Finding bugs with Nuclei with PinkDraconian (Robbe Van Roey)](https://www.youtube.com/watch?v=ewP0xVPW-Pk) by **[@PinkDraconian](https://twitter.com/PinkDraconian)** 
- [Nuclei: Packing a Punch with Vulnerability Scanning](https://bishopfox.com/blog/nuclei-vulnerability-scan) by **Bishopfox**
- [The WAF efficacy framework](https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf) by **Fastly**
- [Scanning Live Web Applications with Nuclei in CI/CD Pipeline](https://blog.escape.tech/devsecops-part-iii-scanning-live-web-applications/) by **[@TristanKalos](https://twitter.com/TristanKalos)**
- [Community Powered Scanning with Nuclei](https://blog.projectdiscovery.io/community-powered-scanning-with-nuclei/)
- [Nuclei Unleashed - Quickly write complex exploits](https://blog.projectdiscovery.io/nuclei-unleashed-quickly-write-complex-exploits/)
- [Nuclei - Fuzz all the things](https://blog.projectdiscovery.io/nuclei-fuzz-all-the-things/)
- [Nuclei + Interactsh Integration for Automating OOB Testing](https://blog.projectdiscovery.io/nuclei-interactsh-integration/)
- [Weaponizes nuclei Workflows to Pwn All the Things](https://medium.com/@dwisiswant0/weaponizes-nuclei-workflows-to-pwn-all-the-things-cd01223feb77) by **[@dwisiswant0](https://github.com/dwisiswant0)**
- [How to Scan Continuously with Nuclei?](https://medium.com/@dwisiswant0/how-to-scan-continuously-with-nuclei-fcb7e9d8b8b9) by **[@dwisiswant0](https://github.com/dwisiswant0)**
- [Hack with Automation !!!](https://dhiyaneshgeek.github.io/web/security/2021/07/19/hack-with-automation/) by **[@DhiyaneshGeek](https://github.com/DhiyaneshGeek)**

### Credits

Thanks to all the amazing community [contributors for sending PRs](https://github.com/projectdiscovery/nuclei/graphs/contributors). Do also check out the below similar open-source projects that may fit in your workflow:

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### License

Nuclei is distributed under [MIT License](https://github.com/projectdiscovery/nuclei/blob/master/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/projectdiscovery"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://nuclei.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>
