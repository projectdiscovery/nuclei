



## Template
Template is a YAML input file which defines all the requests and
 other metadata for a template.






<hr />

<div class="dd">

<code>id</code>  <i>string</i>

</div>
<div class="dt">

ID is the unique id for the template.

#### Good IDs

A good ID uniquely identifies what the requests in the template
are doing. Let's say you have a template that identifies a git-config
file on the webservers, a good name would be `git-config-exposure`. Another
example name is `azure-apps-nxdomain-takeover`.



Examples:


```yaml
# ID Example
id: CVE-2021-19520
```


</div>

<hr />

<div class="dd">

<code>info</code>  <i><a href="#modelinfo">model.Info</a></i>

</div>
<div class="dt">

Info contains metadata information about the template.



Examples:


```yaml
info:
    name: Argument Injection in Ruby Dragonfly
    author: 0xspara
    tags: cve,cve2021,rce,ruby
    reference: https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/
    severity: high
```


</div>

<hr />

<div class="dd">

<code>requests</code>  <i>[]<a href="#httprequest">http.Request</a></i>

</div>
<div class="dt">

Requests contains the http request to make in the template.



Examples:


```yaml
requests:
    matchers:
        - type: word
          words:
            - '[core]'
        - type: dsl
          condition: and
          dsl:
            - '!contains(tolower(body), ''<html'')'
            - '!contains(tolower(body), ''<body'')'
        - type: status
          status:
            - 200
    matchers-condition: and
    path:
        - '{{BaseURL}}/.git/config'
    method: GET
```


</div>

<hr />

<div class="dd">

<code>dns</code>  <i>[]<a href="#dnsrequest">dns.Request</a></i>

</div>
<div class="dt">

DNS contains the dns request to make in the template



Examples:


```yaml
dns:
    extractors:
        - type: regex
          regex:
            - ec2-[-\d]+\.compute[-\d]*\.amazonaws\.com
            - ec2-[-\d]+\.[\w\d\-]+\.compute[-\d]*\.amazonaws\.com
    name: '{{FQDN}}'
    type: CNAME
    class: inet
    retries: 2
    recursion: false
```


</div>

<hr />

<div class="dd">

<code>file</code>  <i>[]<a href="#filerequest">file.Request</a></i>

</div>
<div class="dt">

File contains the file request to make in the template



Examples:


```yaml
file:
    extractors:
        - type: regex
          regex:
            - amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
    extensions:
        - all
```


</div>

<hr />

<div class="dd">

<code>network</code>  <i>[]<a href="#networkrequest">network.Request</a></i>

</div>
<div class="dt">

Network contains the network request to make in the template



Examples:


```yaml
network:
    host:
        - '{{Hostname}}'
        - '{{Hostname}}:2181'
    inputs:
        - data: "envi\r\nquit\r\n"
    read-size: 2048
    matchers:
        - type: word
          words:
            - zookeeper.version
```


</div>

<hr />

<div class="dd">

<code>headless</code>  <i>[]<a href="#headlessrequest">headless.Request</a></i>

</div>
<div class="dt">

Headless contains the headless request to make in the template.

</div>

<hr />

<div class="dd">

<code>ssl</code>  <i>[]<a href="#sslrequest">ssl.Request</a></i>

</div>
<div class="dt">

SSL contains the SSL request to make in the template.

</div>

<hr />

<div class="dd">

<code>websocket</code>  <i>[]<a href="#websocketrequest">websocket.Request</a></i>

</div>
<div class="dt">

Websocket contains the Websocket request to make in the template.

</div>

<hr />

<div class="dd">

<code>whois</code>  <i>[]<a href="#whoisrequest">whois.Request</a></i>

</div>
<div class="dt">

WHOIS contains the WHOIS request to make in the template.

</div>

<hr />

<div class="dd">

<code>workflows</code>  <i>[]<a href="#workflowsworkflowtemplate">workflows.WorkflowTemplate</a></i>

</div>
<div class="dt">

Workflows is a list of workflows to execute for a template.

</div>

<hr />

<div class="dd">

<code>self-contained</code>  <i>bool</i>

</div>
<div class="dt">

Self Contained marks Requests for the template as self-contained

</div>

<hr />

<div class="dd">

<code>stop-at-first-match</code>  <i>bool</i>

</div>
<div class="dt">

Stop execution once first match is found

</div>

<hr />

<div class="dd">

<code>signature</code>  <i><a href="#httpsignaturetypeholder">http.SignatureTypeHolder</a></i>

</div>
<div class="dt">

Signature is the request signature method


Valid values:


  - <code>AWS</code>
</div>

<hr />





## model.Info
Info contains metadata information about a template

Appears in:


- <code><a href="#template">Template</a>.info</code>


```yaml
name: Argument Injection in Ruby Dragonfly
author: 0xspara
tags: cve,cve2021,rce,ruby
reference: https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/
severity: high
```



<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name should be good short summary that identifies what the template does.



Examples:


```yaml
name: bower.json file disclosure
```

```yaml
name: Nagios Default Credentials Check
```


</div>

<hr />

<div class="dd">

<code>author</code>  <i><a href="#stringslicestringslice">stringslice.StringSlice</a></i>

</div>
<div class="dt">

Author of the template.

Multiple values can also be specified separated by commas.



Examples:


```yaml
author: <username>
```


</div>

<hr />

<div class="dd">

<code>tags</code>  <i><a href="#stringslicestringslice">stringslice.StringSlice</a></i>

</div>
<div class="dt">

Any tags for the template.

Multiple values can also be specified separated by commas.



Examples:


```yaml
# Example tags
tags: cve,cve2019,grafana,auth-bypass,dos
```


</div>

<hr />

<div class="dd">

<code>description</code>  <i>string</i>

</div>
<div class="dt">

Description of the template.

You can go in-depth here on what the template actually does.



Examples:


```yaml
description: Bower is a package manager which stores package information in the bower.json file
```

```yaml
description: Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations
```


</div>

<hr />

<div class="dd">

<code>reference</code>  <i><a href="#stringslicestringslice">stringslice.StringSlice</a></i>

</div>
<div class="dt">

References for the template.

This should contain links relevant to the template.



Examples:


```yaml
reference:
    - https://github.com/strapi/strapi
    - https://github.com/getgrav/grav
```


</div>

<hr />

<div class="dd">

<code>severity</code>  <i><a href="#severityholder">severity.Holder</a></i>

</div>
<div class="dt">

Severity of the template.

</div>

<hr />

<div class="dd">

<code>metadata</code>  <i>map[string]string</i>

</div>
<div class="dt">

Metadata of the template.



Examples:


```yaml
metadata:
    customField1: customValue1
```


</div>

<hr />

<div class="dd">

<code>classification</code>  <i><a href="#modelclassification">model.Classification</a></i>

</div>
<div class="dt">

Classification contains classification information about the template.

</div>

<hr />

<div class="dd">

<code>remediation</code>  <i>string</i>

</div>
<div class="dt">

Remediation steps for the template.

You can go in-depth here on how to mitigate the problem found by this template.



Examples:


```yaml
remediation: Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties
```


</div>

<hr />





## stringslice.StringSlice
StringSlice represents a single (in-lined) or multiple string value(s).
 The unmarshaller does not automatically convert in-lined strings to []string, hence the interface{} type is required.

Appears in:


- <code><a href="#modelinfo">model.Info</a>.author</code>

- <code><a href="#modelinfo">model.Info</a>.tags</code>

- <code><a href="#modelinfo">model.Info</a>.reference</code>

- <code><a href="#modelclassification">model.Classification</a>.cve-id</code>

- <code><a href="#modelclassification">model.Classification</a>.cwe-id</code>

- <code><a href="#workflowsworkflowtemplate">workflows.WorkflowTemplate</a>.tags</code>


```yaml
<username>
```
```yaml
# Example tags
cve,cve2019,grafana,auth-bypass,dos
```
```yaml
- https://github.com/strapi/strapi
- https://github.com/getgrav/grav
```
```yaml
CVE-2020-14420
```
```yaml
CWE-22
```





## severity.Holder
Holder holds a Severity type. Required for un/marshalling purposes

Appears in:


- <code><a href="#modelinfo">model.Info</a>.severity</code>





<hr />

<div class="dd">

<code></code>  <i>Severity</i>

</div>
<div class="dt">




Enum Values:


  - <code>undefined</code>

  - <code>info</code>

  - <code>low</code>

  - <code>medium</code>

  - <code>high</code>

  - <code>critical</code>
</div>

<hr />





## model.Classification

Appears in:


- <code><a href="#modelinfo">model.Info</a>.classification</code>





<hr />

<div class="dd">

<code>cve-id</code>  <i><a href="#stringslicestringslice">stringslice.StringSlice</a></i>

</div>
<div class="dt">

CVE ID for the template



Examples:


```yaml
cve-id: CVE-2020-14420
```


</div>

<hr />

<div class="dd">

<code>cwe-id</code>  <i><a href="#stringslicestringslice">stringslice.StringSlice</a></i>

</div>
<div class="dt">

CWE ID for the template.



Examples:


```yaml
cwe-id: CWE-22
```


</div>

<hr />

<div class="dd">

<code>cvss-metrics</code>  <i>string</i>

</div>
<div class="dt">

CVSS Metrics for the template.



Examples:


```yaml
cvss-metrics: 3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```


</div>

<hr />

<div class="dd">

<code>cvss-score</code>  <i>float64</i>

</div>
<div class="dt">

CVSS Score for the template.



Examples:


```yaml
cvss-score: "9.8"
```


</div>

<hr />





## http.Request
Request contains a http request to be made from a template

Appears in:


- <code><a href="#template">Template</a>.requests</code>


```yaml
matchers:
    - type: word
      words:
        - '[core]'
    - type: dsl
      condition: and
      dsl:
        - '!contains(tolower(body), ''<html'')'
        - '!contains(tolower(body), ''<body'')'
    - type: status
      status:
        - 200
matchers-condition: and
path:
    - '{{BaseURL}}/.git/config'
method: GET
```

Part Definitions: 


- <code>template-id</code> - ID of the template executed
- <code>template-info</code> - Info Block of the template executed
- <code>template-path</code> - Path of the template executed
- <code>host</code> - Host is the input to the template
- <code>matched</code> - Matched is the input which was matched upon
- <code>type</code> - Type is the type of request made
- <code>request</code> - HTTP request made from the client
- <code>response</code> - HTTP response recieved from server
- <code>status_code</code> - Status Code received from the Server
- <code>body</code> - HTTP response body received from server (default)
- <code>content_length</code> - HTTP Response content length
- <code>header,all_headers</code> - HTTP response headers
- <code>duration</code> - HTTP request time duration
- <code>all</code> - HTTP response body + headers
- <code>cookies_from_response</code> - HTTP response cookies in name:value format
- <code>headers_from_response</code> - HTTP response headers in name:value format

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />

<div class="dd">

<code>path</code>  <i>[]string</i>

</div>
<div class="dt">

Path contains the path/s for the HTTP requests. It supports variables
as placeholders.



Examples:


```yaml
# Some example path values
path:
    - '{{BaseURL}}'
    - '{{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions'
```


</div>

<hr />

<div class="dd">

<code>raw</code>  <i>[]string</i>

</div>
<div class="dt">

Raw contains HTTP Requests in Raw format.



Examples:


```yaml
# Some example raw requests
raw:
    - |-
      GET /etc/passwd HTTP/1.1
      Host:
      Content-Length: 4
    - |-
      POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1
      Host: {{Hostname}}
      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
      Content-Length: 1
      Connection: close

      echo
      echo
      cat /etc/passwd 2>&1
```


</div>

<hr />

<div class="dd">

<code>id</code>  <i>string</i>

</div>
<div class="dt">

ID is the optional id of the request

</div>

<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name is the optional name of the request.

If a name is specified, all the named request in a template can be matched upon
in a combined manner allowing multi-request based matchers.

</div>

<hr />

<div class="dd">

<code>attack</code>  <i><a href="#generatorsattacktypeholder">generators.AttackTypeHolder</a></i>

</div>
<div class="dt">

Attack is the type of payload combinations to perform.

batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.


Valid values:


  - <code>batteringram</code>

  - <code>pitchfork</code>

  - <code>clusterbomb</code>
</div>

<hr />

<div class="dd">

<code>method</code>  <i><a href="#httpmethodtypeholder">HTTPMethodTypeHolder</a></i>

</div>
<div class="dt">

Method is the HTTP Request Method.

</div>

<hr />

<div class="dd">

<code>body</code>  <i>string</i>

</div>
<div class="dt">

Body is an optional parameter which contains HTTP Request body.



Examples:


```yaml
# Same Body for a Login POST request
body: username=test&password=test
```


</div>

<hr />

<div class="dd">

<code>payloads</code>  <i>map[string]interface{}</i>

</div>
<div class="dt">

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

</div>

<hr />

<div class="dd">

<code>headers</code>  <i>map[string]string</i>

</div>
<div class="dt">

Headers contains HTTP Headers to send with the request.



Examples:


```yaml
headers:
    Any-Header: Any-Value
    Content-Length: "1"
    Content-Type: application/x-www-form-urlencoded
```


</div>

<hr />

<div class="dd">

<code>race_count</code>  <i>int</i>

</div>
<div class="dt">

RaceCount is the number of times to send a request in Race Condition Attack.



Examples:


```yaml
# Send a request 5 times
race_count: 5
```


</div>

<hr />

<div class="dd">

<code>max-redirects</code>  <i>int</i>

</div>
<div class="dt">

MaxRedirects is the maximum number of redirects that should be followed.



Examples:


```yaml
# Follow up to 5 redirects
max-redirects: 5
```


</div>

<hr />

<div class="dd">

<code>pipeline-concurrent-connections</code>  <i>int</i>

</div>
<div class="dt">

PipelineConcurrentConnections is number of connections to create during pipelining.



Examples:


```yaml
# Create 40 concurrent connections
pipeline-concurrent-connections: 40
```


</div>

<hr />

<div class="dd">

<code>pipeline-requests-per-connection</code>  <i>int</i>

</div>
<div class="dt">

PipelineRequestsPerConnection is number of requests to send per connection when pipelining.



Examples:


```yaml
# Send 100 requests per pipeline connection
pipeline-requests-per-connection: 100
```


</div>

<hr />

<div class="dd">

<code>threads</code>  <i>int</i>

</div>
<div class="dt">

Threads specifies number of threads to use sending requests. This enables Connection Pooling.

Connection: Close attribute must not be used in request while using threads flag, otherwise
pooling will fail and engine will continue to close connections after requests.



Examples:


```yaml
# Send requests using 10 concurrent threads
threads: 10
```


</div>

<hr />

<div class="dd">

<code>max-size</code>  <i>int</i>

</div>
<div class="dt">

MaxSize is the maximum size of http response body to read in bytes.



Examples:


```yaml
# Read max 2048 bytes of the response
max-size: 2048
```


</div>

<hr />

<div class="dd">

<code>signature</code>  <i><a href="#signaturetypeholder">SignatureTypeHolder</a></i>

</div>
<div class="dt">

Signature is the request signature method


Valid values:


  - <code>AWS</code>
</div>

<hr />

<div class="dd">

<code>cookie-reuse</code>  <i>bool</i>

</div>
<div class="dt">

CookieReuse is an optional setting that enables cookie reuse for
all requests defined in raw section.

</div>

<hr />

<div class="dd">

<code>redirects</code>  <i>bool</i>

</div>
<div class="dt">

Redirects specifies whether redirects should be followed by the HTTP Client.

This can be used in conjunction with `max-redirects` to control the HTTP request redirects.

</div>

<hr />

<div class="dd">

<code>pipeline</code>  <i>bool</i>

</div>
<div class="dt">

Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining

All requests must be idempotent (GET/POST). This can be used for race conditions/billions requests.

</div>

<hr />

<div class="dd">

<code>unsafe</code>  <i>bool</i>

</div>
<div class="dt">

Unsafe specifies whether to use rawhttp engine for sending Non RFC-Compliant requests.

This uses the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine to achieve complete
control over the request, with no normalization performed by the client.

</div>

<hr />

<div class="dd">

<code>race</code>  <i>bool</i>

</div>
<div class="dt">

Race determines if all the request have to be attempted at the same time (Race Condition)

The actual number of requests that will be sent is determined by the `race_count`  field.

</div>

<hr />

<div class="dd">

<code>req-condition</code>  <i>bool</i>

</div>
<div class="dt">

ReqCondition automatically assigns numbers to requests and preserves their history.

This allows matching on them later for multi-request conditions.

</div>

<hr />

<div class="dd">

<code>stop-at-first-match</code>  <i>bool</i>

</div>
<div class="dt">

StopAtFirstMatch stops the execution of the requests and template as soon as a match is found.

</div>

<hr />

<div class="dd">

<code>skip-variables-check</code>  <i>bool</i>

</div>
<div class="dt">

SkipVariablesCheck skips the check for unresolved variables in request

</div>

<hr />

<div class="dd">

<code>iterate-all</code>  <i>bool</i>

</div>
<div class="dt">

IterateAll iterates all the values extracted from internal extractors

</div>

<hr />





## matchers.Matcher
Matcher is used to match a part in the output from a protocol.

Appears in:


- <code><a href="#httprequest">http.Request</a>.matchers</code>

- <code><a href="#dnsrequest">dns.Request</a>.matchers</code>

- <code><a href="#filerequest">file.Request</a>.matchers</code>

- <code><a href="#networkrequest">network.Request</a>.matchers</code>

- <code><a href="#headlessrequest">headless.Request</a>.matchers</code>

- <code><a href="#sslrequest">ssl.Request</a>.matchers</code>

- <code><a href="#websocketrequest">websocket.Request</a>.matchers</code>

- <code><a href="#whoisrequest">whois.Request</a>.matchers</code>





<hr />

<div class="dd">

<code>type</code>  <i><a href="#matchertypeholder">MatcherTypeHolder</a></i>

</div>
<div class="dt">

Type is the type of the matcher.

</div>

<hr />

<div class="dd">

<code>condition</code>  <i>string</i>

</div>
<div class="dt">

Condition is the optional condition between two matcher variables. By default,
the condition is assumed to be OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />

<div class="dd">

<code>part</code>  <i>string</i>

</div>
<div class="dt">

Part is the part of the request response to match data from.

Each protocol exposes a lot of different parts which are well
documented in docs for each request type.



Examples:


```yaml
part: body
```

```yaml
part: raw
```


</div>

<hr />

<div class="dd">

<code>negative</code>  <i>bool</i>

</div>
<div class="dt">

Negative specifies if the match should be reversed
It will only match if the condition is not true.

</div>

<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name of the matcher. Name should be lowercase and must not contain
spaces or underscores (_).



Examples:


```yaml
name: cookie-matcher
```


</div>

<hr />

<div class="dd">

<code>status</code>  <i>[]int</i>

</div>
<div class="dt">

Status are the acceptable status codes for the response.



Examples:


```yaml
status:
    - 200
    - 302
```


</div>

<hr />

<div class="dd">

<code>size</code>  <i>[]int</i>

</div>
<div class="dt">

Size is the acceptable size for the response



Examples:


```yaml
size:
    - 3029
    - 2042
```


</div>

<hr />

<div class="dd">

<code>words</code>  <i>[]string</i>

</div>
<div class="dt">

Words contains word patterns required to be present in the response part.



Examples:


```yaml
# Match for Outlook mail protection domain
words:
    - mail.protection.outlook.com
```

```yaml
# Match for application/json in response headers
words:
    - application/json
```


</div>

<hr />

<div class="dd">

<code>regex</code>  <i>[]string</i>

</div>
<div class="dt">

Regex contains Regular Expression patterns required to be present in the response part.



Examples:


```yaml
# Match for Linkerd Service via Regex
regex:
    - (?mi)^Via\\s*?:.*?linkerd.*$
```

```yaml
# Match for Open Redirect via Location header
regex:
    - (?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)example\\.com.*$
```


</div>

<hr />

<div class="dd">

<code>binary</code>  <i>[]string</i>

</div>
<div class="dt">

Binary are the binary patterns required to be present in the response part.



Examples:


```yaml
# Match for Springboot Heapdump Actuator "JAVA PROFILE", "HPROF", "Gunzip magic byte"
binary:
    - 4a4156412050524f46494c45
    - 4850524f46
    - 1f8b080000000000
```

```yaml
# Match for 7zip files
binary:
    - 377ABCAF271C
```


</div>

<hr />

<div class="dd">

<code>dsl</code>  <i>[]string</i>

</div>
<div class="dt">

DSL are the dsl expressions that will be evaluated as part of nuclei matching rules.
A list of these helper functions are available [here](https://nuclei.projectdiscovery.io/templating-guide/helper-functions/).



Examples:


```yaml
# DSL Matcher for package.json file
dsl:
    - contains(body, 'packages') && contains(tolower(all_headers), 'application/octet-stream') && status_code == 200
```

```yaml
# DSL Matcher for missing strict transport security header
dsl:
    - '!contains(tolower(all_headers), ''''strict-transport-security'''')'
```


</div>

<hr />

<div class="dd">

<code>encoding</code>  <i>string</i>

</div>
<div class="dt">

Encoding specifies the encoding for the words field if any.


Valid values:


  - <code>hex</code>
</div>

<hr />

<div class="dd">

<code>case-insensitive</code>  <i>bool</i>

</div>
<div class="dt">

CaseInsensitive enables case-insensitive matches. Default is false.


Valid values:


  - <code>false</code>

  - <code>true</code>
</div>

<hr />





## MatcherTypeHolder
MatcherTypeHolder is used to hold internal type of the matcher

Appears in:


- <code><a href="#matchersmatcher">matchers.Matcher</a>.type</code>





<hr />

<div class="dd">

<code></code>  <i>MatcherType</i>

</div>
<div class="dt">




Enum Values:


  - <code>word</code>

  - <code>regex</code>

  - <code>binary</code>

  - <code>status</code>

  - <code>size</code>

  - <code>dsl</code>
</div>

<hr />





## extractors.Extractor
Extractor is used to extract part of response using a regex.

Appears in:


- <code><a href="#httprequest">http.Request</a>.extractors</code>

- <code><a href="#dnsrequest">dns.Request</a>.extractors</code>

- <code><a href="#filerequest">file.Request</a>.extractors</code>

- <code><a href="#networkrequest">network.Request</a>.extractors</code>

- <code><a href="#headlessrequest">headless.Request</a>.extractors</code>

- <code><a href="#sslrequest">ssl.Request</a>.extractors</code>

- <code><a href="#websocketrequest">websocket.Request</a>.extractors</code>

- <code><a href="#whoisrequest">whois.Request</a>.extractors</code>





<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name of the extractor. Name should be lowercase and must not contain
spaces or underscores (_).



Examples:


```yaml
name: cookie-extractor
```


</div>

<hr />

<div class="dd">

<code>type</code>  <i><a href="#extractortypeholder">ExtractorTypeHolder</a></i>

</div>
<div class="dt">

Type is the type of the extractor.

</div>

<hr />

<div class="dd">

<code>regex</code>  <i>[]string</i>

</div>
<div class="dt">

Regex contains the regular expression patterns to extract from a part.

Go regex engine does not support lookaheads or lookbehinds, so as a result
they are also not supported in nuclei.



Examples:


```yaml
# Braintree Access Token Regex
regex:
    - access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}
```

```yaml
# Wordpress Author Extraction regex
regex:
    - Author:(?:[A-Za-z0-9 -\_="]+)?<span(?:[A-Za-z0-9 -\_="]+)?>([A-Za-z0-9]+)<\/span>
```


</div>

<hr />

<div class="dd">

<code>group</code>  <i>int</i>

</div>
<div class="dt">

Group specifies a numbered group to extract from the regex.



Examples:


```yaml
# Example Regex Group
group: 1
```


</div>

<hr />

<div class="dd">

<code>kval</code>  <i>[]string</i>

</div>
<div class="dt">

description: |
   kval contains the key-value pairs present in the HTTP response header.
   kval extractor can be used to extract HTTP response header and cookie key-value pairs.
   kval extractor inputs are case-insensitive, and does not support dash (-) in input which can replaced with underscores (_)
 	 For example, Content-Type should be replaced with content_type

   A list of supported parts is available in docs for request types.
 examples:
   - name: Extract Server Header From HTTP Response
     value: >
       []string{"server"}
   - name: Extracting value of PHPSESSID Cookie
     value: >
       []string{"phpsessid"}
   - name: Extracting value of Content-Type Cookie
     value: >
       []string{"content_type"}

</div>

<hr />

<div class="dd">

<code>json</code>  <i>[]string</i>

</div>
<div class="dt">

JSON allows using jq-style syntax to extract items from json response



Examples:


```yaml
json:
    - .[] | .id
```

```yaml
json:
    - .batters | .batter | .[] | .id
```


</div>

<hr />

<div class="dd">

<code>xpath</code>  <i>[]string</i>

</div>
<div class="dt">

XPath allows using xpath expressions to extract items from html response



Examples:


```yaml
xpath:
    - /html/body/div/p[2]/a
```


</div>

<hr />

<div class="dd">

<code>attribute</code>  <i>string</i>

</div>
<div class="dt">

Attribute is an optional attribute to extract from response XPath.



Examples:


```yaml
attribute: href
```


</div>

<hr />

<div class="dd">

<code>part</code>  <i>string</i>

</div>
<div class="dt">

Part is the part of the request response to extract data from.

Each protocol exposes a lot of different parts which are well
documented in docs for each request type.



Examples:


```yaml
part: body
```

```yaml
part: raw
```


</div>

<hr />

<div class="dd">

<code>internal</code>  <i>bool</i>

</div>
<div class="dt">

Internal, when set to true will allow using the value extracted
in the next request for some protocols (like HTTP).

</div>

<hr />

<div class="dd">

<code>case-insensitive</code>  <i>bool</i>

</div>
<div class="dt">

CaseInsensitive enables case-insensitive extractions. Default is false.


Valid values:


  - <code>false</code>

  - <code>true</code>
</div>

<hr />





## ExtractorTypeHolder
ExtractorTypeHolder is used to hold internal type of the extractor

Appears in:


- <code><a href="#extractorsextractor">extractors.Extractor</a>.type</code>





<hr />

<div class="dd">

<code></code>  <i>ExtractorType</i>

</div>
<div class="dt">




Enum Values:


  - <code>regex</code>

  - <code>kval</code>

  - <code>xpath</code>

  - <code>json</code>
</div>

<hr />





## generators.AttackTypeHolder
AttackTypeHolder is used to hold internal type of the protocol

Appears in:


- <code><a href="#httprequest">http.Request</a>.attack</code>

- <code><a href="#networkrequest">network.Request</a>.attack</code>

- <code><a href="#websocketrequest">websocket.Request</a>.attack</code>





<hr />

<div class="dd">

<code></code>  <i>AttackType</i>

</div>
<div class="dt">




Enum Values:


  - <code>batteringram</code>

  - <code>pitchfork</code>

  - <code>clusterbomb</code>
</div>

<hr />





## HTTPMethodTypeHolder
HTTPMethodTypeHolder is used to hold internal type of the HTTP Method

Appears in:


- <code><a href="#httprequest">http.Request</a>.method</code>





<hr />

<div class="dd">

<code></code>  <i>HTTPMethodType</i>

</div>
<div class="dt">




Enum Values:


  - <code>GET</code>

  - <code>GET</code>

  - <code>POST</code>

  - <code>PUT</code>

  - <code>DELETE</code>

  - <code>CONNECT</code>

  - <code>OPTIONS</code>

  - <code>TRACE</code>

  - <code>PATCH</code>

  - <code>PURGE</code>
</div>

<hr />





## SignatureTypeHolder
SignatureTypeHolder is used to hold internal type of the signature

Appears in:


- <code><a href="#httprequest">http.Request</a>.signature</code>







## dns.Request
Request contains a DNS protocol request to be made from a template

Appears in:


- <code><a href="#template">Template</a>.dns</code>


```yaml
extractors:
    - type: regex
      regex:
        - ec2-[-\d]+\.compute[-\d]*\.amazonaws\.com
        - ec2-[-\d]+\.[\w\d\-]+\.compute[-\d]*\.amazonaws\.com
name: '{{FQDN}}'
type: CNAME
class: inet
retries: 2
recursion: false
```

Part Definitions: 


- <code>template-id</code> - ID of the template executed
- <code>template-info</code> - Info Block of the template executed
- <code>template-path</code> - Path of the template executed
- <code>host</code> - Host is the input to the template
- <code>matched</code> - Matched is the input which was matched upon
- <code>request</code> - Request contains the DNS request in text format
- <code>type</code> - Type is the type of request made
- <code>rcode</code> - Rcode field returned for the DNS request
- <code>question</code> - Question contains the DNS question field
- <code>extra</code> - Extra contains the DNS response extra field
- <code>answer</code> - Answer contains the DNS response answer field
- <code>ns</code> - NS contains the DNS response NS field
- <code>raw,body,all</code> - Raw contains the raw DNS response (default)
- <code>trace</code> - Trace contains trace data for DNS request if enabled

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />

<div class="dd">

<code>id</code>  <i>string</i>

</div>
<div class="dt">

ID is the optional id of the request

</div>

<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name is the Hostname to make DNS request for.

Generally, it is set to {{FQDN}} which is the domain we get from input.



Examples:


```yaml
name: '{{FQDN}}'
```


</div>

<hr />

<div class="dd">

<code>type</code>  <i><a href="#dnsrequesttypeholder">DNSRequestTypeHolder</a></i>

</div>
<div class="dt">

RequestType is the type of DNS request to make.

</div>

<hr />

<div class="dd">

<code>class</code>  <i>string</i>

</div>
<div class="dt">

Class is the class of the DNS request.

Usually it's enough to just leave it as INET.


Valid values:


  - <code>inet</code>

  - <code>csnet</code>

  - <code>chaos</code>

  - <code>hesiod</code>

  - <code>none</code>

  - <code>any</code>
</div>

<hr />

<div class="dd">

<code>retries</code>  <i>int</i>

</div>
<div class="dt">

Retries is the number of retries for the DNS request



Examples:


```yaml
# Use a retry of 3 to 5 generally
retries: 5
```


</div>

<hr />

<div class="dd">

<code>trace</code>  <i>bool</i>

</div>
<div class="dt">

Trace performs a trace operation for the target.

</div>

<hr />

<div class="dd">

<code>trace-max-recursion</code>  <i>int</i>

</div>
<div class="dt">

TraceMaxRecursion is the number of max recursion allowed for trace operations



Examples:


```yaml
# Use a retry of 100 to 150 generally
trace-max-recursion: 100
```


</div>

<hr />

<div class="dd">

<code>recursion</code>  <i>dns.bool</i>

</div>
<div class="dt">

Recursion determines if resolver should recurse all records to get fresh results.

</div>

<hr />

<div class="dd">

<code>resolvers</code>  <i>[]string</i>

</div>
<div class="dt">

Resolvers to use for the dns requests

</div>

<hr />





## DNSRequestTypeHolder
DNSRequestTypeHolder is used to hold internal type of the DNS type

Appears in:


- <code><a href="#dnsrequest">dns.Request</a>.type</code>





<hr />

<div class="dd">

<code></code>  <i>DNSRequestType</i>

</div>
<div class="dt">




Enum Values:


  - <code>A</code>

  - <code>NS</code>

  - <code>DS</code>

  - <code>CNAME</code>

  - <code>SOA</code>

  - <code>PTR</code>

  - <code>MX</code>

  - <code>TXT</code>

  - <code>AAAA</code>
</div>

<hr />





## file.Request
Request contains a File matching mechanism for local disk operations.

Appears in:


- <code><a href="#template">Template</a>.file</code>


```yaml
extractors:
    - type: regex
      regex:
        - amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
extensions:
    - all
```

Part Definitions: 


- <code>template-id</code> - ID of the template executed
- <code>template-info</code> - Info Block of the template executed
- <code>template-path</code> - Path of the template executed
- <code>matched</code> - Matched is the input which was matched upon
- <code>path</code> - Path is the path of file on local filesystem
- <code>type</code> - Type is the type of request made
- <code>raw,body,all,data</code> - Raw contains the raw file contents

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />

<div class="dd">

<code>extensions</code>  <i>[]string</i>

</div>
<div class="dt">

Extensions is the list of extensions to perform matching on.



Examples:


```yaml
extensions:
    - .txt
    - .go
    - .json
```


</div>

<hr />

<div class="dd">

<code>denylist</code>  <i>[]string</i>

</div>
<div class="dt">

DenyList is the list of file, directories or extensions to deny during matching.

By default, it contains some non-interesting extensions that are hardcoded
in nuclei.



Examples:


```yaml
denylist:
    - .avi
    - .mov
    - .mp3
```


</div>

<hr />

<div class="dd">

<code>id</code>  <i>string</i>

</div>
<div class="dt">

ID is the optional id of the request

</div>

<hr />

<div class="dd">

<code>max-size</code>  <i>int</i>

</div>
<div class="dt">

MaxSize is the maximum size of the file to run request on.

By default, nuclei will process 5 MB files and not go more than that.
It can be set to much lower or higher depending on use.



Examples:


```yaml
max-size: 2048
```


</div>

<hr />

<div class="dd">

<code>no-recursive</code>  <i>bool</i>

</div>
<div class="dt">

NoRecursive specifies whether to not do recursive checks if folders are provided.

</div>

<hr />





## network.Request
Request contains a Network protocol request to be made from a template

Appears in:


- <code><a href="#template">Template</a>.network</code>


```yaml
host:
    - '{{Hostname}}'
    - '{{Hostname}}:2181'
inputs:
    - data: "envi\r\nquit\r\n"
read-size: 2048
matchers:
    - type: word
      words:
        - zookeeper.version
```

Part Definitions: 


- <code>template-id</code> - ID of the template executed
- <code>template-info</code> - Info Block of the template executed
- <code>template-path</code> - Path of the template executed
- <code>host</code> - Host is the input to the template
- <code>matched</code> - Matched is the input which was matched upon
- <code>type</code> - Type is the type of request made
- <code>request</code> - Network request made from the client
- <code>body,all,data</code> - Network response recieved from server (default)
- <code>raw</code> - Full Network protocol data

<hr />

<div class="dd">

<code>id</code>  <i>string</i>

</div>
<div class="dt">

ID is the optional id of the request

</div>

<hr />

<div class="dd">

<code>host</code>  <i>[]string</i>

</div>
<div class="dt">

Host to send network requests to.

Usually it's set to `{{Hostname}}`. If you want to enable TLS for
TCP Connection, you can use `tls://{{Hostname}}`.



Examples:


```yaml
host:
    - '{{Hostname}}'
```


</div>

<hr />

<div class="dd">

<code>attack</code>  <i><a href="#generatorsattacktypeholder">generators.AttackTypeHolder</a></i>

</div>
<div class="dt">

Attack is the type of payload combinations to perform.

Batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

</div>

<hr />

<div class="dd">

<code>payloads</code>  <i>map[string]interface{}</i>

</div>
<div class="dt">

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

</div>

<hr />

<div class="dd">

<code>inputs</code>  <i>[]<a href="#networkinput">network.Input</a></i>

</div>
<div class="dt">

Inputs contains inputs for the network socket

</div>

<hr />

<div class="dd">

<code>read-size</code>  <i>int</i>

</div>
<div class="dt">

ReadSize is the size of response to read at the end

Default value for read-size is 1024.



Examples:


```yaml
read-size: 2048
```


</div>

<hr />

<div class="dd">

<code>read-all</code>  <i>bool</i>

</div>
<div class="dt">

ReadAll determines if the data stream should be read till the end regardless of the size

Default value for read-all is false.



Examples:


```yaml
read-all: false
```


</div>

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />





## network.Input

Appears in:


- <code><a href="#networkrequest">network.Request</a>.inputs</code>





<hr />

<div class="dd">

<code>data</code>  <i>string</i>

</div>
<div class="dt">

Data is the data to send as the input.

It supports DSL Helper Functions as well as normal expressions.



Examples:


```yaml
data: TEST
```

```yaml
data: hex_decode('50494e47')
```


</div>

<hr />

<div class="dd">

<code>type</code>  <i><a href="#networkinputtypeholder">NetworkInputTypeHolder</a></i>

</div>
<div class="dt">

Type is the type of input specified in `data` field.

Default value is text, but hex can be used for hex formatted data.


Valid values:


  - <code>hex</code>

  - <code>text</code>
</div>

<hr />

<div class="dd">

<code>read</code>  <i>int</i>

</div>
<div class="dt">

Read is the number of bytes to read from socket.

This can be used for protocols which expect an immediate response. You can
read and write responses one after another and eventually perform matching
on every data captured with `name` attribute.

The [network docs](https://nuclei.projectdiscovery.io/templating-guide/protocols/network/) highlight more on how to do this.



Examples:


```yaml
read: 1024
```


</div>

<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name is the optional name of the data read to provide matching on.



Examples:


```yaml
name: prefix
```


</div>

<hr />





## NetworkInputTypeHolder
NetworkInputTypeHolder is used to hold internal type of the Network type

Appears in:


- <code><a href="#networkinput">network.Input</a>.type</code>





<hr />

<div class="dd">

<code></code>  <i>NetworkInputType</i>

</div>
<div class="dt">




Enum Values:


  - <code>hex</code>

  - <code>text</code>
</div>

<hr />





## headless.Request
Request contains a Headless protocol request to be made from a template

Appears in:


- <code><a href="#template">Template</a>.headless</code>



Part Definitions: 


- <code>template-id</code> - ID of the template executed
- <code>template-info</code> - Info Block of the template executed
- <code>template-path</code> - Path of the template executed
- <code>host</code> - Host is the input to the template
- <code>matched</code> - Matched is the input which was matched upon
- <code>type</code> - Type is the type of request made
- <code>req</code> - Headless request made from the client
- <code>resp,body,data</code> - Headless response recieved from client (default)

<hr />

<div class="dd">

<code>id</code>  <i>string</i>

</div>
<div class="dt">

ID is the optional id of the request

</div>

<hr />

<div class="dd">

<code>steps</code>  <i>[]<a href="#engineaction">engine.Action</a></i>

</div>
<div class="dt">

Steps is the list of actions to run for headless request

</div>

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />





## engine.Action
Action is an action taken by the browser to reach a navigation

 Each step that the browser executes is an action. Most navigations
 usually start from the ActionLoadURL event, and further navigations
 are discovered on the found page. We also keep track and only
 scrape new navigation from pages we haven't crawled yet.

Appears in:


- <code><a href="#headlessrequest">headless.Request</a>.steps</code>





<hr />

<div class="dd">

<code>args</code>  <i>map[string]string</i>

</div>
<div class="dt">

Args contain arguments for the headless action.
Per action arguments are described in detail [here](https://nuclei.projectdiscovery.io/templating-guide/protocols/headless/).

</div>

<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name is the name assigned to the headless action.

This can be used to execute code, for instance in browser
DOM using script action, and get the result in a variable
which can be matched upon by nuclei. An Example template [here](https://github.com/projectdiscovery/nuclei-templates/blob/master/headless/prototype-pollution-check.yaml).

</div>

<hr />

<div class="dd">

<code>description</code>  <i>string</i>

</div>
<div class="dt">

Description is the optional description of the headless action

</div>

<hr />

<div class="dd">

<code>action</code>  <i><a href="#actiontypeholder">ActionTypeHolder</a></i>

</div>
<div class="dt">

Action is the type of the action to perform.

</div>

<hr />





## ActionTypeHolder
ActionTypeHolder is used to hold internal type of the action

Appears in:


- <code><a href="#engineaction">engine.Action</a>.action</code>





<hr />

<div class="dd">

<code></code>  <i>ActionType</i>

</div>
<div class="dt">




Enum Values:


  - <code>navigate</code>

  - <code>script</code>

  - <code>click</code>

  - <code>rightclick</code>

  - <code>text</code>

  - <code>screenshot</code>

  - <code>time</code>

  - <code>select</code>

  - <code>files</code>

  - <code>waitload</code>

  - <code>getresource</code>

  - <code>extract</code>

  - <code>setmethod</code>

  - <code>addheader</code>

  - <code>setheader</code>

  - <code>deleteheader</code>

  - <code>setbody</code>

  - <code>waitevent</code>

  - <code>keyboard</code>

  - <code>debug</code>

  - <code>sleep</code>

  - <code>waitvisible</code>
</div>

<hr />





## ssl.Request
Request is a request for the SSL protocol

Appears in:


- <code><a href="#template">Template</a>.ssl</code>



Part Definitions: 


- <code>type</code> - Type is the type of request made
- <code>response</code> - JSON SSL protocol handshake details
- <code>not_after</code> - Timestamp after which the remote cert expires
- <code>host</code> - Host is the input to the template
- <code>matched</code> - Matched is the input which was matched upon

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />

<div class="dd">

<code>address</code>  <i>string</i>

</div>
<div class="dt">

Address contains address for the request

</div>

<hr />





## websocket.Request
Request is a request for the Websocket protocol

Appears in:


- <code><a href="#template">Template</a>.websocket</code>



Part Definitions: 


- <code>type</code> - Type is the type of request made
- <code>success</code> - Success specifies whether websocket connection was successful
- <code>request</code> - Websocket request made to the server
- <code>response</code> - Websocket response recieved from the server
- <code>host</code> - Host is the input to the template
- <code>matched</code> - Matched is the input which was matched upon

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />

<div class="dd">

<code>address</code>  <i>string</i>

</div>
<div class="dt">

Address contains address for the request

</div>

<hr />

<div class="dd">

<code>inputs</code>  <i>[]<a href="#websocketinput">websocket.Input</a></i>

</div>
<div class="dt">

Inputs contains inputs for the websocket protocol

</div>

<hr />

<div class="dd">

<code>headers</code>  <i>map[string]string</i>

</div>
<div class="dt">

Headers contains headers for the request.

</div>

<hr />

<div class="dd">

<code>attack</code>  <i><a href="#generatorsattacktypeholder">generators.AttackTypeHolder</a></i>

</div>
<div class="dt">

Attack is the type of payload combinations to perform.

Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates
permutations and combinations for all payloads.

</div>

<hr />

<div class="dd">

<code>payloads</code>  <i>map[string]interface{}</i>

</div>
<div class="dt">

Payloads contains any payloads for the current request.

Payloads support both key-values combinations where a list
of payloads is provided, or optionally a single file can also
be provided as payload which will be read on run-time.

</div>

<hr />





## websocket.Input

Appears in:


- <code><a href="#websocketrequest">websocket.Request</a>.inputs</code>





<hr />

<div class="dd">

<code>data</code>  <i>string</i>

</div>
<div class="dt">

Data is the data to send as the input.

It supports DSL Helper Functions as well as normal expressions.



Examples:


```yaml
data: TEST
```

```yaml
data: hex_decode('50494e47')
```


</div>

<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name is the optional name of the data read to provide matching on.



Examples:


```yaml
name: prefix
```


</div>

<hr />





## whois.Request
Request is a request for the WHOIS protocol

Appears in:


- <code><a href="#template">Template</a>.whois</code>





<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#matchersmatcher">matchers.Matcher</a></i>

</div>
<div class="dt">

Matchers contains the detection mechanism for the request to identify
whether the request was successful by doing pattern matching
on request/responses.

Multiple matchers can be combined with `matcher-condition` flag
which accepts either `and` or `or` as argument.

</div>

<hr />

<div class="dd">

<code>extractors</code>  <i>[]<a href="#extractorsextractor">extractors.Extractor</a></i>

</div>
<div class="dt">

Extractors contains the extraction mechanism for the request to identify
and extract parts of the response.

</div>

<hr />

<div class="dd">

<code>matchers-condition</code>  <i>string</i>

</div>
<div class="dt">

MatchersCondition is the condition between the matchers. Default is OR.


Valid values:


  - <code>and</code>

  - <code>or</code>
</div>

<hr />

<div class="dd">

<code>query</code>  <i>string</i>

</div>
<div class="dt">

Query contains query for the request

</div>

<hr />

<div class="dd">

<code>server</code>  <i>string</i>

</div>
<div class="dt">

description: |
 	 Optional WHOIS server URL.

 	 If present, specifies the WHOIS server to execute the Request on.
   Otherwise, nil enables bootstrapping

</div>

<hr />





## workflows.WorkflowTemplate

Appears in:


- <code><a href="#template">Template</a>.workflows</code>

- <code><a href="#workflowsworkflowtemplate">workflows.WorkflowTemplate</a>.subtemplates</code>

- <code><a href="#workflowsmatcher">workflows.Matcher</a>.subtemplates</code>





<hr />

<div class="dd">

<code>template</code>  <i>string</i>

</div>
<div class="dt">

Template is a single template or directory to execute as part of workflow.



Examples:


```yaml
# A single template
template: dns/worksites-detection.yaml
```

```yaml
# A template directory
template: misconfigurations/aem
```


</div>

<hr />

<div class="dd">

<code>tags</code>  <i><a href="#stringslicestringslice">stringslice.StringSlice</a></i>

</div>
<div class="dt">

Tags to run templates based on.

</div>

<hr />

<div class="dd">

<code>matchers</code>  <i>[]<a href="#workflowsmatcher">workflows.Matcher</a></i>

</div>
<div class="dt">

Matchers perform name based matching to run subtemplates for a workflow.

</div>

<hr />

<div class="dd">

<code>subtemplates</code>  <i>[]<a href="#workflowsworkflowtemplate">workflows.WorkflowTemplate</a></i>

</div>
<div class="dt">

Subtemplates are run if the `template` field Template matches.

</div>

<hr />





## workflows.Matcher

Appears in:


- <code><a href="#workflowsworkflowtemplate">workflows.WorkflowTemplate</a>.matchers</code>





<hr />

<div class="dd">

<code>name</code>  <i>string</i>

</div>
<div class="dt">

Name is the name of the item to match.

</div>

<hr />

<div class="dd">

<code>subtemplates</code>  <i>[]<a href="#workflowsworkflowtemplate">workflows.WorkflowTemplate</a></i>

</div>
<div class="dt">

Subtemplates are run if the name of matcher matches.

</div>

<hr />





## http.SignatureTypeHolder
SignatureTypeHolder is used to hold internal type of the signature

Appears in:


- <code><a href="#template">Template</a>.signature</code>






