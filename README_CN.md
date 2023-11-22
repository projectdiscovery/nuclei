<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">基于YAML语法模板的定制化快速漏洞扫描器</h4>


<p align="center">
<img src="https://img.shields.io/github/go-mod/go-version/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases"><img src="https://img.shields.io/github/downloads/projectdiscovery/nuclei/total">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors"><img src="https://img.shields.io/github/contributors-anon/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/releases/"><img src="https://img.shields.io/github/release/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/issues"><img src="https://img.shields.io/github/issues-raw/projectdiscovery/nuclei">
<a href="https://github.com/projectdiscovery/nuclei/discussions"><img src="https://img.shields.io/github/discussions/projectdiscovery/nuclei">
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
</p>

<p align="center">
  <a href="#工作流程">工作流程</a> •
  <a href="#安装Nuclei">安装</a> •
  <a href="#对于安全工程师">对于安全工程师</a> •
  <a href="#对于开发和组织">对于开发者</a> •
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/">文档</a> •
  <a href="#c致谢">致谢</a> •
  <a href="https://nuclei.projectdiscovery.io/faq/nuclei/">常见问题</a> •
  <a href="https://discord.gg/projectdiscovery">加入Discord</a>
</p>

<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README.md">English</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_CN.md">中文</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_KR.md">Korean</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/main/README_ID.md">Indonesia</a>
</p>

---

Nuclei使用零误报的定制模板向目标发送请求，同时可以对主机进行批量快速扫描。Nuclei提供TCP、DNS、HTTP、FILE等各类协议的扫描，通过强大且灵活的模板，可以使用Nuclei模拟各种安全检查。

我们的[模板仓库](https://github.com/projectdiscovery/nuclei-templates)包含**超过300**安全研究员和工程师提供的模板。



## 工作流程


<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>

| :exclamation:  **免责声明**  |
|---------------------------------|
| **这个项目正在积极开发中**。预计发布会带来突破性的更改。更新前请查看版本更改日志。 |
| 这个项目主要是为了作为一个独立的命令行工具而构建的。 **将Nuclei作为服务运行可能存在安全风险。** 强烈建议谨慎使用，并采取额外的安全措施。 |

# 安装Nuclei

Nuclei需要**go1**才能安装成功。执行下列命令安装最新版本的Nuclei

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

**更多的安装方式 [请点击此处](https://nuclei.projectdiscovery.io/nuclei/get-started/).**

<table>
<tr>
<td>  

### Nuclei模板

自从[v2.5.2]((https://github.com/projectdiscovery/nuclei/releases/tag/v2.5.2))起，Nuclei就内置了自动下载和更新模板的功能。[**Nuclei模板**](https://github.com/projectdiscovery/nuclei-templates)仓库随时更新社区中可用的模板列表。

您仍然可以随时使用`update-templates`命令更新模板，您可以根据[模板指南](https://nuclei.projectdiscovery.io/templating-guide/)为您的个人工作流和需求编写模板。

YAML的语法规范在[这里](SYNTAX-REFERENCE.md)。

</td>
</tr>
</table>

### 用法

```sh
nuclei -h
```

这将显示Nuclei的帮助，以下是所有支持的命令。


```console
Nuclei是一款注重于可配置性、可扩展性和易用性的基于模板的快速漏洞扫描器。

用法：
  nuclei [命令]

命令：
目标：
   -u, -target string[]                  指定扫描的目标URL/主机（多个目标则指定多个-u参数）
   -l, -list string                      指定包含要扫描的目标URL/主机列表的文件路径（一行一个）
   -resume string                        使用指定的resume.cfg文件恢复扫描（将禁用请求聚类）
   -sa, -scan-all-ips                    扫描由目标解析出来的所有IP（针对域名对应多个IP的情况）
   -iv, -ip-version string[]             要扫描的主机名的IP版本（4,6）-（默认为4）

模板：
   -nt, -new-templates                    仅运行最新发布的nuclei模板
   -ntv, -new-templates-version string[]  仅运行特定版本中添加的新模板
   -as, -automatic-scan                   基于Wappalyzer技术的标签映射自动扫描
   -t, -templates string[]                指定要运行的模板或者模板目录（以逗号分隔或目录形式）
   -turl, -template-url string[]          指定要运行的模板URL或模板目录URL（以逗号分隔或目录形式）
   -w, -workflows string[]                指定要运行的工作流或工作流目录（以逗号分隔或目录形式）
   -wurl, -workflow-url string[]          指定要运行的工作流URL或工作流目录URL（以逗号分隔或目录形式）
   -validate                              使用nuclei验证模板有效性
   -nss, -no-strict-syntax                禁用对模板的严格检查
   -td, -template-display                 显示模板内容
   -tl                                    列出所有可用的模板
   -sign                                  使用NUCLEI_SIGNATURE_PRIVATE_KEY环境变量中的私钥对模板进行签名
   -code                                  启用加载基于协议的代码模板

过滤：
   -a, -author string[]                  执行指定作者的模板（逗号分隔，文件）
   -tags string[]                        执行带指定tag的模板（逗号分隔，文件）
   -etags, -exclude-tags string[]        排除带指定tag的模板（逗号分隔，文件）
   -itags, -include-tags string[]        执行带有指定tag的模板，即使是被默认或者配置排除的模板
   -id, -template-id string[]            执行指定id的模板（逗号分隔，文件）
   -eid, -exclude-id string[]            排除指定id的模板（逗号分隔，文件）
   -it, -include-templates string[]      执行指定模板，即使是被默认或配置排除的模板
   -et, -exclude-templates string[]      排除指定模板或者模板目录（逗号分隔，文件）
   -em, -exclude-matchers string[]       排除指定模板matcher
   -s, -severity value[]                 根据严重程度运行模板，可选值有：info,low,medium,high,critical   
   -es, -exclude-severity value[]        根据严重程度排除模板，可选值有：info,low,medium,high,critical
   -pt, -type value[]                    根据类型运行模板，可选值有：dns, file, http, headless, network, workflow, ssl, websocket, whois
   -ept, -exclude-type value[]           根据类型排除模板，可选值有：dns, file, http, headless, network, workflow, ssl, websocket, whois
   -tc, -template-condition string[]     根据表达式运行模板
   

输出：
   -o, -output string                    输出发现的问题到文件
   -sresp, -store-resp                   将nuclei的所有请求和响应输出到目录
   -srd, -store-resp-dir string          将nuclei的所有请求和响应输出到指定目录（默认：output）
   -silent                               只显示结果
   -nc, -no-color                        禁用输出内容着色（ANSI转义码）
   -j, -jsonl                            输出格式为jsonL（ines）
   -irr, -include-rr                     在JSON、JSONL和Markdown中输出请求/响应对（仅结果）[已弃用，使用-omit-raw替代]
   -or, -omit-raw                        在JSON、JSONL和Markdown中不输出请求/响应对
   -ot, -omit-template           省略JSON、JSONL输出中的编码模板
   -nm, -no-meta                         在cli输出中不打印元数据
   -ts, -timestamp                       在cli输出中打印时间戳
   -rdb, -report-db string               本地的nuclei结果数据库（始终使用该数据库保存结果）
   -ms, -matcher-status                  显示匹配失败状态
   -me, -markdown-export string          以markdown格式导出结果
   -se, -sarif-export string             以SARIF格式导出结果
   -je, -json-export string              以JSON格式导出结果
   -jle, -jsonl-export string            以JSONL(ine)格式导出结果


配置：
   -config string                        指定nuclei的配置文件
   -fr, -follow-redirects                为HTTP模板启用重定向
   -fhr, -follow-host-redirects          允许在同一主机上重定向
   -mr, -max-redirects int               HTTP模板最大重定向次数（默认：10）
   -dr, -disable-redirects               为HTTP模板禁用重定向
   -rc, -report-config string            指定nuclei报告模板文件
   -H, -header string[]                  指定在所有http请求中包含的自定义header、cookie，以header:value的格式指定（cli，文件）
   -V, -var value                        以key=value格式自定义变量
   -r, -resolvers string                 指定包含DNS解析服务列表的文件
   -sr, -system-resolvers                当DNS错误时使用系统DNS解析服务
   -dc, -disable-clustering              关闭请求聚类功能
   -passive                              启用被动模式处理本地HTTP响应数据
   -fh2, -force-http2                    强制使用http2连接
   -ev, env-vars                         启用在模板中使用环境变量
   -cc, -client-cert string              用于对扫描的主机进行身份验证的客户端证书文件（PEM 编码）
   -ck, -client-key string               用于对扫描的主机进行身份验证的客户端密钥文件（PEM 编码）
   -ca, -client-ca string                用于对扫描的主机进行身份验证的客户端证书颁发机构文件（PEM 编码）
   -sml, -show-match-line                显示文件模板的匹配值，只适用于提取器
   -ztls                                 使用ztls库，带有自动回退到标准库tls13 [已弃用] 默认情况下启用对ztls的自动回退
   -sni string                           指定tls sni的主机名（默认为输入的域名）
   -lfa, -allow-local-file-access        允许访问本地文件（payload文件）
   -lna, -restrict-local-network-access  阻止对本地/私有网络的连接
   -i, -interface string                 指定用于网络扫描的网卡
   -at, -attack-type string              payload的组合模式（batteringram,pitchfork,clusterbomb）
   -sip, -source-ip string               指定用于网络扫描的源IP
   -rsr, -response-size-read int         最大读取响应大小（默认：10485760字节）
   -rss, -response-size-save int         最大储存响应大小（默认：1048576字节）
   -reset                                删除所有nuclei配置和数据文件（包括nuclei-templates）
   -tlsi, -tls-impersonate               启用实验性的Client Hello（ja3）TLS 随机化功能


交互：
   -inserver, -ineractsh-server string   使用interactsh反连检测平台（默认为oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me）
   -itoken, -interactsh-token string     指定反连检测平台的身份凭证
   -interactions-cache-size int          指定保存在交互缓存中的请求数（默认：5000）
   -interactions-eviction int            从缓存中删除请求前等待的时间（默认为60秒）
   -interactions-poll-duration int       每个轮询前等待时间（默认为5秒）
   -interactions-cooldown-period int     退出轮询前的等待时间（默认为5秒）
   -ni, -no-interactsh                   禁用反连检测平台，同时排除基于反连检测的模板


模糊测试:
   -ft, -fuzzing-type string             覆盖模板中设置的模糊测试类型（replace、prefix、postfix、infix）
   -fm, -fuzzing-mode string             覆盖模板中设置的模糊测试模式（multiple、single）


UNCOVER引擎:
   -uc, -uncover                         启动uncover引擎
   -uq, -uncover-query string[]          uncover查询语句
   -ue, -uncover-engine string[]         指定uncover查询引擎 （shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow） （默认 shodan）
   -uf, -uncover-field string            查询字段 （ip,port,host） （默认 "ip:port"）
   -ul, -uncover-limit int               查询结果数 （默认 100）
   -ur, -uncover-ratelimit int           查询速率，默认每分钟60个请求（默认 60）


限速：
   -rl, -rate-limit int                  每秒最大请求量（默认：150）
   -rlm, -rate-limit-minute int          每分钟最大请求量
   -bs, -bulk-size int                   每个模板最大并行检测数（默认：25）
   -c, -concurrency int                  并行执行的最大模板数量（默认：25）
   -hbs, -headless-bulk-size int         每个模板并行运行的无头主机最大数量（默认：10）
   -headc, -headless-concurrency int     并行指定无头主机最大数量（默认：10）


优化：
   -timeout int                          超时时间（默认为10秒）
   -retries int                          重试次数（默认：1）
   -ldp, -leave-default-ports            指定HTTP/HTTPS默认端口（例如：host:80，host:443）
   -mhe, -max-host-error int             某主机扫描失败次数，跳过该主机（默认：30）
   -te, -track-error string[]            将给定错误添加到最大主机错误监视列表（标准、文件）
   -nmhe, -no-mhe                        disable skipping host from scan based on errors
   -project                              使用项目文件夹避免多次发送同一请求
   -project-path string                  设置特定的项目文件夹
   -spm, -stop-at-first-path             得到一个结果后停止（或许会中断模板和工作流的逻辑）
   -stream                               流模式 - 在不整理输入的情况下详细描述
   -ss, -scan-strategy value             扫描时使用的策略（auto/host-spray/template-spray） （默认 auto）
   -irt, -input-read-timeout duration    输入读取超时时间（默认：3分钟）
   -nh, -no-httpx                        禁用对非URL输入进行httpx探测
   -no-stdin                             禁用标准输入

无界面浏览器：
    -headless                            启用需要无界面浏览器的模板
    -page-timeout int                    在无界面下超时秒数（默认：20）
    -sb, -show-brower                    在无界面浏览器运行模板时，显示浏览器
    -ho, -headless-options string[]      使用附加选项启动无界面浏览器
    -sc, -system-chrome                  不使用Nuclei自带的浏览器，使用本地浏览器
    -lha, -list-headless-action          列出可用的无界面操作

调试：
    -debug                               显示所有请求和响应
    -dreq, -debug-req                    显示所有请求
    -dresp, -debug-resp                  显示所有响应
    -p, -proxy string[]                  使用http/socks5代理（逗号分隔，文件）
    -pi, -proxy-internal                 代理所有请求
    -ldf, -list-dsl-function             列出所有支持的DSL函数签名
    -tlog, -trace-log string             写入跟踪日志到文件
    -elog, -error-log string             写入错误日志到文件
    -version                             显示版本信息
    -hm, -hang-monitor                   启用对nuclei挂起协程的监控
    -v, -verbose                         显示详细信息
    -profile-mem string                  将Nuclei的内存转储成文件
    -vv                                  显示额外的详细信息
    -svd, -show-var-dump                 显示用于调试的变量输出
    -ep, -enable-pprof                   启用pprof调试服务器
    -tv, -templates-version              显示已安装的模板版本
    -hc, -health-check                   运行诊断检查

升级：
    -up, -update                         更新Nuclei到最新版本
    -ut, -update-templates               更新Nuclei模板到最新版
    -ud, -update-template-dir string     指定模板目录
    -duc, -disable-update-check          禁用nuclei程序与模板更新

统计：
    -stats                               显示正在扫描的统计信息
    -sj, -stats-json                     将统计信息以JSONL格式输出到文件
    -si, -stats-inerval int              显示统计信息更新的间隔秒数（默认：5）
    -mp, -metrics-port int               更改metrics服务的端口（默认：9092）

云服务:
   -auth                配置projectdiscovery云（pdcp）API密钥
   -cup, -cloud-upload  将扫描结果上传到pdcp仪表板

例子:
扫描一个单独的URL:
	$ nuclei -target example.com

对URL运行指定的模板:
	$ nuclei -target example.com -t http/cves/ -t ssl

扫描hosts.txt中的多个URL:
	$ nuclei -list hosts.txt

输出结果为JSON格式:
	$ nuclei -target example.com -json-export output.json

使用已排序的Markdown输出（使用环境变量）运行nuclei:
	$ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

```

更多信息请参考文档: https://docs.nuclei.sh/getting-started/running


### 运行Nuclei

使用[社区提供的模板](https://github.com/projectdiscovery/nuclei-templates)扫描单个目标

```sh
nuclei -u https://example.com
```

使用[社区提供的模板](https://github.com/projectdiscovery/nuclei-templates)扫描多个目标

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

**更多关于Nuclei的详细实例可以在[这里](https://nuclei.projectdiscovery.io/nuclei/get-started/#running-nuclei)找到**

# 对于安全工程师

Nuclei提供了大量有助于安全工程师在工作流定制相关的功能。通过各种扫描功能（如DNS、HTTP、TCP），安全工程师可以更轻松的使用Nuclei创建一套自定义的检查方式。

- 支持多种协议：TCP、DNS、HTTP、FILE等
- 通过工作流和动态请求实现复杂的漏洞扫描
- 易于集成到CI/CD，旨在可以轻松的集成到周期扫描中，以主动检测漏洞的修复和重新出现

<h1 align="left">
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

<table>
<tr>
<td>  

**对于赏金猎人：**

Nuclei允许您定制自己的测试方法，可以轻松的运行您的程序。此外Nuclei可以更容易的集成到您的漏洞扫描工作流中。

- 可以集成到其他工作流中
- 可以在几分钟处理上千台主机
- 使用YAML语法定制自动化测试

欢迎查看我们其他的开源项目，可能有适合您的赏金猎人工作流：[github.com/projectdiscovery](http://github.com/projectdiscovery)，我们还使用[Chaos绘制了每日的DNS数据](http://chaos.projectdiscovery.io)。

</td>
</tr>
</table>

<table>
<tr>
<td>

**对于渗透测试：**

Nuclei通过增加手动、自动的过程，极大地改变了安全评估的方式。一些公司已经在用Nuclei升级他们的手动测试步骤，可以使用Nulcei对数千台主机使用同样的流程自动化测试。

渗透测试员可以使用公共模板或者自定义模板来更快的完成渗透测试，特别是漏洞验证时，可以轻松的验证漏洞是否修复。

- 轻松根据您的要求创建标准清单（例如：OWASP TOP 10）
- 通过[FUZZ](https://nuclei.projectdiscovery.io/templating-guide/protocols/http-fuzzing/)和[工作流](https://nuclei.projectdiscovery.io/templating-guide/workflows/)等功能，可以使用Nuclei完成复杂的手动步骤和重复性渗透测试
- 只需要重新运行Nuclei即可验证漏洞修复情况

</td>
</tr>
</table>

# 对于开发和组织

Nuclei构建很简单，通过数百名安全研究员的社区模板，Nuclei可以随时扫描来了解安全威胁。Nuclei通常用来用于复测，以确定漏洞是否被修复。

- **CI/CD：**工程师已经支持了CI/CD，可以通过Nuclei使用定制模板来监控模拟环境和生产环境
- **周期性扫描：**使用Nuclei创建新发现的漏洞模板，通过Nuclei可以周期性扫描消除漏洞

我们有个[讨论组](https://github.com/projectdiscovery/nuclei-templates/discussions/693)，黑客提交自己的模板后可以获得赏金，这可以减少资产的漏洞，并且减少重复。如果你想实行该计划，可以[联系我](mailto:contact@projectdiscovery.io)。我们非常乐意提供帮助，或者在[讨论组](https://github.com/projectdiscovery/nuclei-templates/discussions/693)中发布相关信息。

<h3 align="center">
  <img src="static/regression-with-nuclei.jpg" alt="regression-cycle-with-nuclei" width="1100px"></a>
</h3>

<h1 align="left">
  <a href="https://github.com/projectdiscovery/nuclei-action"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

### 将nuclei加入您的代码

有关使用Nuclei作为Library/SDK的完整指南，请访问[godoc](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib#section-readme)

### 资源

- [使用PinkDraconian发现Nuclei的BUG (Robbe Van Roey)](https://www.youtube.com/watch?v=ewP0xVPW-Pk) 作者：[@PinkDraconian](https://twitter.com/PinkDraconian)
- [Nuclei: 强而有力的扫描器](https://bishopfox.com/blog/nuclei-vulnerability-scan) 作者：Bishopfox
- [WAF有效性检查](https://www.fastly.com/blog/the-waf-efficacy-framework-measuring-the-effectiveness-of-your-waf) 作者：Fastly
- [在CI/CD中使用Nuclei实时扫描网页应用](https://blog.escape.tech/devsecops-part-iii-scanning-live-web-applications/) 作者：[@TristanKalos](https://twitter.com/TristanKalos)
- [使用Nuclei扫描](https://blog.projectdiscovery.io/community-powered-scanning-with-nuclei/)
- [Nuclei Unleashed - 快速编写复杂漏洞](https://blog.projectdiscovery.io/nuclei-unleashed-quickly-write-complex-exploits/)
- [Nuclei - FUZZ一切](https://blog.projectdiscovery.io/nuclei-fuzz-all-the-things/)
- [Nuclei + Interactsh Integration，用于自动化OOB测试](https://blog.projectdiscovery.io/nuclei-interactsh-integration/)
- [武器化Nuclei](https://medium.com/@dwisiswant0/weaponizes-nuclei-workflows-to-pwn-all-the-things-cd01223feb77) 作者：[@dwisiswant0](https://github.com/dwisiswant0)
- [如何使用Nuclei连续扫描？](https://medium.com/@dwisiswant0/how-to-scan-continuously-with-nuclei-fcb7e9d8b8b9) 作者：[@dwisiswant0](https://github.com/dwisiswant0)
- [自动化攻击](https://dhiyaneshgeek.github.io/web/security/2021/07/19/hack-with-automation/) 作者：[@DhiyaneshGeek](https://github.com/DhiyaneshGeek)

### 致谢

感谢所有[社区贡献者提供的PR](https://github.com/projectdiscovery/nuclei/graphs/contributors)，并不断更新此项目:heart:

如果你有想法或某种改进，欢迎你参与该项目，随时发送你的PR。

<p align="center">
<a href="https://github.com/projectdiscovery/nuclei/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=projectdiscovery/nuclei&max=500">
</a>
</p>

另外您可以其他类似的开源项目：

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### 许可证

Nuclei使用[MIT许可证](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/projectdiscovery"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://nuclei.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>
