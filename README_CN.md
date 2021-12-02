<h1 align="center">
  <br>
  <a href="https://nuclei.projectdiscovery.io"><img src="static/nuclei-logo.png" width="200px" alt="Nuclei"></a>
</h1>

<h4 align="center">基于YAML语法模板的定制化快速漏洞扫描器</h4>


<p align="center">
<a href="https://goreportcard.com/report/github.com/projectdiscovery/nuclei"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/nuclei"></a>
<a href="https://github.com/projectdiscovery/nuclei/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/projectdiscovery/nuclei/releases"><img src="https://img.shields.io/github/release/projectdiscovery/nuclei"></a>
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
<a href="https://github.com/projectdiscovery/nuclei/actions/workflows/build-test.yml"><img src="https://github.com/projectdiscovery/nuclei/actions/workflows/build-test.yml/badge.svg?branch=master"></a>
</p>
      
<p align="center">
  <a href="#工作流程">工作流程</a> •
  <a href="#安装Nuclei">安装</a> •
  <a href="#对于安全工程师">对于安全工程师</a> •
  <a href="#对于开发者和组织">对于开发者</a> •
  <a href="https://nuclei.projectdiscovery.io/nuclei/get-started/">文档</a> •
  <a href="#c致谢">致谢</a> •
  <a href="https://nuclei.projectdiscovery.io/faq/nuclei/">常见问题</a> •
  <a href="https://discord.gg/projectdiscovery">加入Discord</a>
</p>

<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei/blob/master/README.md">English</a> •
  <a href="https://github.com/projectdiscovery/nuclei/blob/master/README_CN.md">中文</a>
</p>

---

Nuclei使用零误报的定制模板向目标发送请求，同时可以对大量主机进行快速扫描。Nuclei提供TCP、DNS、HTTP、FILE等各类协议的扫描，通过强大且灵活的模板，可以使用Nuclei模拟各种安全检查。

我们的[模板仓库](https://github.com/projectdiscovery/nuclei-templates)包含**超过200**安全研究员和工程师提供的模板。



## 工作流程


<h3 align="center">
  <img src="static/nuclei-flow.jpg" alt="nuclei-flow" width="700px"></a>
</h3>


# 安装Nuclei

Nuclei需要**go1.17**才能安装成功。执行下列命令安装最新版本的Nuclei

```sh
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

**更多的安装方式 [请点击此处](https://nuclei.projectdiscovery.io/nuclei/get-started/).**

<table>
<tr>
<td>  

### Nuclei模板

自从[v2.5.2]((https://github.com/projectdiscovery/nuclei/releases/tag/v2.5.2))起，Nuclei就内置了自动下载和更新模板的功能。[**Nuclei模板**](https://github.com/projectdiscovery/nuclei-templates)仓库随时更新社区中可用的模板列表。

您仍然可以随时使用`update-templates`命令更新模板，您可以根据[模板指南](https://nuclei.projectdiscovery.io/templating-guide/)编写您自己的模板。

YAML的语法规范在[这里](SYNTAX-REFERENCE.md)。

</td>
</tr>
</table>

### 用法

```sh
nuclei -h
```

这将显示Nuclei的帮助，以下是所有支持的命令


```yaml
Nuclei是一款注重于可配置性、可扩展性和易用性的基于模板的快速漏洞扫描器。

用法：
  nuclei [命令]

命令：
目标：
   -u, -target string[]                 指定扫描的URL/主机
   -l, -list string                     指定需要扫描的URL/主机文件（一行一个）

模板：
   -t, -templates string[]              指定需要扫描的模板或者模板的路径
   -nt, -new-templates                  只扫描最新版本中添加的模板
   -w, -workflows string[]              指定扫描中的工作流或者工作流目录
   -validate                            验证通过的模板
   -tl                                  列出所有可用的模板

过滤：
   -tags string[]                       执行有标记的模板子集
   -etags, -exclude-tags string[]       执行标记为排除的模板
   -itags, -include-tags string[]       不执行具有攻击性的模板
   -et, -exclude-templates string[]     要排除的模板或者模板目录
   -it, -include-templates string[]     执行默认或配置中排除的模板
   -s, -severity value[]                根据严重性运行模板，允许的值有：info,low,medium,high,critical   
   -es, -exclude-severity value[]       根据严重性排除模板，允许的值有：info,low,medium,high,critical   
   -a, -author string[]                 执行指定作者的模板

输出：
   -o, -output string                   输出发现的问题到文件
   -silent                              只显示结果
   -nc, -no-color                       禁用输出内容着色（ANSI转义码）
   -json                                输出为jsonL（ines）
   -irr, -include-rr                    在JSONL中输出对应的请求和相应（仅结果）
   -nm, -no-meta                        不显示匹配的元数据
   -nts, -no-timestamp                  不在输出中显示时间戳
   -rdb, -report-db string              本地的Nuclei结果数据库（始终使用该数据库保存结果）       
   -me, -markdown-export string         以markdown导出结果
   -se, -sarif-export string            以SARIF导出结果

配置：
   -config string                       指定Nuclei的配置文件
   -rc, -report-config string           指定Nuclei报告模板文件
   -H, -header string[]                 指定报告中的标题：value格式
   -V, -var value                       通过var=value指定var值
   -r, -resolvers string                指定Nuclei的解析文件
   -sr, -system-resolvers               当DNS错误时使用系统DNS
   -passive                             启用被动扫描处理HTTP响应
   -ev, env-vars                        在模板中使用环境变量

交互：
   -inserver, -ineractsh-server string  使用interactsh反连检测平台（默认为"https://interactsh.com"）
   -itoken, -interactsh-token string    指定反连检测平台的身份凭证
   -interactions-cache-size int         指定保存在交互缓存中的请求数（默认：5000）
   -interactions-eviction int           聪缓存中删除请求前等待的时间（默认为60秒）
   -interactions-poll-duration int      每个轮询前等待时间（默认为5秒）
   -interactions-cooldown-period int    退出轮询前的等待时间（默认为5秒）
   -ni, -no-interactsh                  禁用反连检测平台，同时排除基于反连检测的模板

限速：
   -r1, -rate-limit int                 每秒最大请求量（默认：150）
   -rlm, -rate-limit-minute int         每分钟最大请求量
   -bs, -bulk-size int                  每个模板最大并行检测数（默认：25）
   -c, -concurrency int                 并行执行的最大模板数量（默认：25）


优化：
   -timeout int                         超时时间（默认为5秒）
   -retries int                         重试次数（默认：1）
   -mhe, -max-host-error int            某主机扫描失败次数，跳过该主机（默认：30）
   -project                             使用项目文件夹避免多次发送同一请求
   -project-path string                 设置特定的项目文件夹
   -spm, -stop-at-first-path            得到一个结果后停止（或许会中断模板和工作流的逻辑）
   -stream                              流模式 - 在不整理输入的情况下详细描述

无界面浏览器：
    -headless                           启用需要无界面浏览器的模板
    -page-timeout int                   在无界面下超时秒数（默认：20）
    -sb, -show-brower                   在无界面浏览器运行模板时，显示浏览器
    -sc, -system-chrome                 不使用Nuclei自带的浏览器，使用本地浏览器

调试：
    -debug                              显示所有请求和响应
    -debug-req                          显示所有请求
    -debug-resp                         显示所有响应
    -proxy, -proxy-url string           使用HTTP代理
    -proxy-socks-url string             使用SOCK5代理
    -tlog, -trace-log string            写入请求日志到文件
    -version                            显示版本信息
    -v, -verbose                        显示详细信息
    -vv                                 显示额外的详细信息
    -tv, -templates-version             显示已安装的模板版本

升级：
    -update                             更新Nuclei到最新版本
    -ut, -update-templates              更新Nuclei模板到最新版
    -ud, -update-directory string       覆盖安装模板
    -duc, -disable-update-check         禁用更新

统计：
    -stats                              显示正在扫描的统计信息
    -sj, -stats-json                    将统计信息以JSONL格式输出到文件
    -si, -stats-inerval int             显示统计信息更新的间隔秒数（默认：5）
    -m, -metrics                        显示Nuclei端口信息
    -mp, -metrics-port int              更改Nuclei默认端口（默认：9092）
```

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

Nuclei允许您定制自己的测试方法，可以轻松的运行您的程序。此外Nuclei可以更容易的集成到您的漏扫设备中。

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
- 通过[FUZZ](https://nuclei.projectdiscovery.io/templating-guide/#advance-fuzzing)和[工作流](https://nuclei.projectdiscovery.io/templating-guide/#workflows)等功能，可以使用Nuclei完成复杂的手动步骤和重复性渗透测试
- 只需要重新运行Nuclei即可验证漏洞修复情况

</td>
</tr>
</table>

# 对于开发和组织

Nuclei构建很简单，通过数百名安全研究员的社区模板，Nuclei可以随时扫描来了解安全威胁。Nuclei通常用来用于复测，以确定漏洞是否被修复。

- **CI/CD：**工程师已经支持了CI/CD，可以使用Nuclei来监控生产环境
- **周期性扫描：**使用Nuclei创建新发现的漏洞模板，通过Nuclei可以周期性扫描消除漏洞

我们有个[讨论组](https://github.com/projectdiscovery/nuclei-templates/discussions/693)，黑客提交自己的模板后可以获得赏金，这可以减少资产的漏洞，并且减少重复。如果你想实行该计划，可以[联系我](mailto:contact@projectdiscovery.io)。我们非常乐意提供帮助，或者在[讨论组](https://github.com/projectdiscovery/nuclei-templates/discussions/693)中发布相关信息。

<h3 align="center">
  <img src="static/regression-with-nuclei.jpg" alt="regression-cycle-with-nuclei" width="1100px"></a>
</h3>

<h1 align="left">
  <a href="https://github.com/projectdiscovery/nuclei-action"><img src="static/learn-more-button.png" width="170px" alt="Learn More"></a>
</h1>

### 资源
- [使用Nuclei扫描](https://blog.projectdiscovery.io/community-powered-scanning-with-nuclei/)
- [Nuclei Unleashed - 快速编写复杂漏洞](https://blog.projectdiscovery.io/nuclei-unleashed-quickly-write-complex-exploits/)
- [Nuclei - FUZZ一切](https://blog.projectdiscovery.io/nuclei-fuzz-all-the-things/)
- [Nuclei + Interactsh Integration，用于自动化OOB测试](https://blog.projectdiscovery.io/nuclei-interactsh-integration/)
- [武器化Nuclei](https://medium.com/@dwisiswant0/weaponizes-nuclei-workflows-to-pwn-all-the-things-cd01223feb77) 作者：[@dwisiswant0](https://github.com/dwisiswant0)
- [如何使用Nuclei连续扫描？](https://medium.com/@dwisiswant0/how-to-scan-continuously-with-nuclei-fcb7e9d8b8b9) 作者：[@dwisiswant0](https://github.com/dwisiswant0)
- [自动化攻击](https://dhiyaneshgeek.github.io/web/security/2021/07/19/hack-with-automation/) 作者：[@DhiyaneshGeek](https://github.com/DhiyaneshGeek)

### 致谢

感谢所有[社区贡献者提供的PR](https://github.com/projectdiscovery/nuclei/graphs/contributors)，另外您可以其他类似的开源项目：

[FFuF](https://github.com/ffuf/ffuf), [Qsfuzz](https://github.com/ameenmaali/qsfuzz), [Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster), [Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates), [Google tsunami](https://github.com/google/tsunami-security-scanner), [Jaeles](https://github.com/jaeles-project/jaeles), [ChopChop](https://github.com/michelin/ChopChop)

### 许可证

Nuclei使用[MIT许可证](https://github.com/projectdiscovery/nuclei/blob/master/LICENSE.md)

<h1 align="left">
  <a href="https://discord.gg/projectdiscovery"><img src="static/Join-Discord.png" width="380" alt="Join Discord"></a> <a href="https://nuclei.projectdiscovery.io"><img src="static/check-nuclei-documentation.png" width="380" alt="Check Nuclei Documentation"></a>
</h1>
