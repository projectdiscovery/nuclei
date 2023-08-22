# flow

flow is a new template engine/backend introduced in v3 which primarily adds 2 most awaited features
- conditional execution of requests (ex: `flow:  dns() && http()`)
- request execution orchestration (iterate over a slice, request execution order)

both of these features are implemented using javascript (ECMAScript 5.1) and are executed using [goja](https://github.com/dop251/goja) and we can say that flow adds support for request orchestration and conditional execution of requests in templates.

## conditional execution

Many times when writing complex templates we might need to add some extra checks (or conditional statements) before executing certain part of request

A idea example of this would be when bruteforcing wordpress login with default usernames and passwords. we can write a new nuclei template for this it would be something like this
```yaml
id: wordpress-bruteforce
info:
  name: WordPress Login Bruteforce
  author: pdteam
  severity: high

http:
  - method: POST
    path:
      - "{{BaseURL}}/wp-login.php"
    payloads:
      username:
        - admin
        - guest
        - testuser
      password:
        - password123
        - qwertyuiop
        - letmein
    body: "log=§username§&pwd=§password§&wp-submit=Log+In"
    attack: clusterbomb 
    matchers:
      - type: word
        words:
          - "ERROR"
        part: body
        negative: true
```

but if we rethink this template, we can see that we are sending 9 requests without even checking first if the url actually exists or target site is actually a wordpress site. before v3 it was possible to do this by adding a extractor and sending additional content in say url fragment and it would fail if request was not successful and another way would be writing a workflow (2 templates and 1 workflow file i.e total 3 files for 1 template) but this is `hacky` and not a good solution.

With flow in Nuclei v3 we can re-write this template to first check if target is a wordpress site and then execute bruteforce requests.
this can be achieved by doing as simple as `flow: http("check-wp") && http("bruteforce")` 

```yaml
id: wordpress-bruteforce
info:
  name: WordPress Login Bruteforce
  author: pdteam
  severity: high

flow: http("check-wp") && http("bruteforce")

http:
  - id: check-wp
    method: GET
    path:
      - "{{BaseURL}}/wp-login.php"
    
    matchers:
        - type: word
            words:
            - "WordPress"
            part: body
        - type: word
            words:
            - "wp-content"
            part: body
    matchers-condition: and

  - id: bruteforce
    method: POST
    path:
      - "{{BaseURL}}/wp-login.php"
    payloads:
      username:
        - admin
        - guest
        - testuser
      password:
        - password123
        - qwertyuiop
        - letmein
    body: "log=§username§&pwd=§password§&wp-submit=Log+In"
    attack: clusterbomb 
    matchers:
      - type: word
        words:
          - "ERROR"
        part: body
        negative: true
```
**Note:**  this is just a example template with poor matchers. refer 'nuclei-templates' repo for final template

Now we can see the template is straight forward and easy to understand. we are first checking if target is a wordpress site and then executing bruteforce requests. This is just a simple example of conditional execution and flow accepts any Javascript (ECMAScript 5.1) expression/code so you are free to craft any conditional execution logic you want using for , if and whatnot.

## request execution orchestration

`conditional execution` is one simple use case of flow but `flow` is much more powerful than that for example it can be used to
- iterate over a slice of values and execute requests for each value (ex: [dns-flow-probe](testcases/nuclei-flow-dns.yaml))
- extract values from one request and iterate over them and execute requests for each value (ex: [[dns-flow-probe](testcases/nuclei-flow-dns.yaml)](https://github.com/projectdiscovery/nuclei/blob/64098b6567a2d6b7fc3e376d61af73836b3277bb/integration_tests/flow/iterate-values-flow.yaml))
- get/set values from/to template context (global variables)
- print/log values to stdout at xyz condition or while debugging
- adding custom logic during template execution (ex: if status code is 403 then login and then re-run it)
- use any/all ECMAScript 5.1 javascript (like objects,arrays etc) and build/transform variables/input at runtime
- update variables at runtime (ex: when jwt expires update it by using refresh token and then continue execution)
- and a lot more (this is just a tip of iceberg)

orchestration can be understood as nuclei logic bindings for javascript (i.e two way interaction between javascript and nuclei for a specific template)

To better understand orchestration we can try to build a template for vhost enumeration using flow. which usually requires writing / using a new tool
for simple vhost enumeration we need to 
- do a PTR lookup for given ip
- get SSL ceritificate for given ip (i.e tls-grab)
  - extract subject_cn from certificate
  - extract subject_alt_names(SAN) from certificate
  - filter out wildcard prefix from above values
- and finally bruteforce all found vhosts


**Now if we try to implement this in template it would something like this**
```yaml
# send a ssl request to get certificate
ssl:
  - address: "{{Host}}:{{Port}}"

# do a PTR lookup for given ip and get PTR value
dns:
  - name: "{{FQDN}}"
    type: PTR

    matchers:
      - type: word
        words:
          - "IN\tPTR"

    extractors:
      - type: regex
        name: ptrValue
        internal: true
        group: 1
        regex:
          - "IN\tPTR\t(.+)" 

# bruteforce all found vhosts
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{vhost}}

    matchers:
      - type: status
        negative: true
        status:
          - 400
          - 502

    extractors:
      - type: dsl
        dsl:
          - '"VHOST: " + vhost + ", SC: " + status_code + ", CL: " + content_length'                                                                                tarun@macbook:~/Codebase/nuclei/integration_tes
```
**But this template is not yet ready as it is missing core logic i.e how we use all these obtained data and do bruteforce**
and this is where flow comes into picture. it is javascript code with two way bindings to nuclei. if we write javascript code in very simple terms it would be something like this
```javascript
  ssl();
  dns();
  for (let vhost of iterate(template["ssl_subject_cn"],template["ssl_subject_an"])) {
    set("vhost", vhost);
    http(); }
```

With just extra 5 lines of javascript code we can achieve vhost enumeration and run it on scale while also handling filtering of wildcard prefix from vhost values.
In above Js code we are using some Nuclei functions and 1 Map lets understand what they do

- `ssl()` => execute ssl request
- `dns()` => execute dns request
- `template["ssl_subject_cn"]` => get value of `ssl_subject_cn` from template context (global variables)
- `iterate()` => this is a nuclei helper function which iterates any type of value (array,map,string,number) while handling empty / nil values
- `set("vhost",vhost)` => creates new variable `vhost` in template and assigns value of `vhost` to it
- `http()` => execute http request

For such complex use case of vhost enumeration just adding 5 lines of js code using nuclei helper functions we achieved vhost enumeration.

**Is this template ready?**
No, we are still missing one thing i.e subject_cn can contain values like `*.projectdiscovery.io` and we need to remove the prefix `*.` 
there are lot of ways to do this we can either
- use javscript `replace()` function to remove prefix (ex: `vhost.replace("*.","")`)
- use nuclei js helper function `trimLeft()`  (ex: `trimLeft(vhost,"*.")`)
- use dsl helper functions in http request

