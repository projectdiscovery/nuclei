# flow

flow is a new template engine/backend introduced in v3 which primarily adds 2 most awaited features
- conditional execution of requests (ex: `flow:  dns() && http()`)
- request execution orchestration (iterate over a slice, request execution order, if/for statement)

both of these features are implemented using javascript (ECMAScript 5.1) with [goja](https://github.com/dop251/goja) backend.
## conditional execution

Many times when writing complex templates we might need to add some extra checks (or conditional statements) before executing certain part of request

An ideal example of this would be when bruteforcing wordpress login with default usernames and passwords. If we try to write a template for this it would be something like this
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

but if we carefully re-evaluate this template, we can see that template is sending 9 requests without even checking, if the url actually exists or target site is actually a wordpress site. before v3 it was possible to do this by adding a extractor and sending additional content in say url fragment and it would fail if request was not successful and another way would be writing a workflow (2 templates and 1 workflow file i.e total 3 files for 1 template) but this is `hacky` and not a good solution.

With addition of flow in Nuclei v3 we can re-write this template to first check if target is a wordpress site, if yes then bruteforce login with default credentials and this can be achieved by simply adding one line of content  i.e `flow: http("check-wp") && http("bruteforce")`  and nuclei will take care of everything else.

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

The update template now seems straight forward and easy to understand. we are first checking if target is a wordpress site and then executing bruteforce requests. This is just a simple example of conditional execution and flow accepts any Javascript (ECMAScript 5.1) expression/code so you are free to craft any conditional execution logic you want using for,if and whatnot.

## request execution orchestration

`conditional execution` is one simple use case of flow but `flow` is much more powerful than that, for example it can be used to
- iterate over a slice of values and execute requests for each value (ex: [dns-flow-probe](testcases/nuclei-flow-dns.yaml))
- extract values from one request and iterate over them and execute requests for each value ex: [dns-flow-probe](testcases/nuclei-flow-dns.yaml)
- get/set values from/to template context (global variables)
- print/log values to stdout at xyz condition or while debugging
- adding custom logic during template execution (ex: if status code is 403 => login and then re-run it)
- use any/all ECMAScript 5.1 javascript (like objects,arrays etc) and build/transform variables/input at runtime
- update variables at runtime (ex: when jwt expires update it by using refresh token and then continue execution)
- and a lot more (this is just a tip of iceberg)

simply put request execution orchestration can be understood as nuclei logic bindings for javascript (i.e two way interaction between javascript and nuclei for a specific template)

To better understand orchestration we can try to build a template for vhost enumeration using flow. which usually requires writing / using a new tool

**for basic vhost enumeration a template should** 
- do a PTR lookup for given ip
- get SSL ceritificate for given ip (i.e tls-grab)
  - extract subject_cn from certificate
  - extract subject_alt_names(SAN) from certificate
  - filter out wildcard prefix from above values
- and finally bruteforce all found vhosts


**Now if we try to implement this in template it would be**
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
and this is where flow comes into picture. flow is javascript code with two way bindings to nuclei. if we write javascript code to orchestrate vhost enumeration it is as simple as
```javascript
  ssl();
  dns();
  for (let vhost of iterate(template["ssl_subject_cn"],template["ssl_subject_an"])) {
    set("vhost", vhost);
    http(); }
```

With just extra 5 lines of javascript code template can now perform vhost enumeration and this can be run on scale with all awesome features of nuclei with various supported inputs like ASN,CIDR,URL etc


In above Js code we are using some Nuclei JS bindings lets understand what they do

- `ssl()` => execute ssl request
- `dns()` => execute dns request
- `template["ssl_subject_cn"]` => get value of `ssl_subject_cn` from template context (global variables)
- `iterate()` => this is a nuclei helper function which iterates any type of value (array,map,string,number) while handling empty / nil values
- `set("vhost",vhost)` => creates new variable `vhost` in template and assigns value of `vhost` to it
- `http()` => execute http request


This template is now missing one last thing i.e
- removing wildcard prefix (*.) in subject_cn,subject_an
- trailing `.` in PTR value

and this can be done using either JS methods of using DSL helper functions as shown in below template

```yaml
id: vhost-enum-flow

info:
  name: vhost enum flow
  author: tarunKoyalwar
  severity: info
  description: |
    vhost enumeration by extracting potential vhost names from ssl certificate and dns ptr records

flow: |
  ssl();
  dns({hide: true});
  for (let vhost of iterate(template["ssl_subject_cn"],template["ssl_subject_an"])) {
    vhost = vhost.replace("*.", "")
    set("vhost", vhost);
    http();
  }

ssl:
  - address: "{{Host}}:{{Port}}"

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

http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{trim_suffix(vhost, ".")}}

    matchers:
      - type: status
        negative: true
        status:
          - 400
          - 502

    extractors:
      - type: dsl
        dsl:
          - '"VHOST: " + vhost + ", SC: " + status_code + ", CL: " + content_length'
```


### Nuclei JS Bindings

This section contains a brief description of all nuclei JS bindings and their usage

**1. Protocol Execution Functions**

  Any protocol that is present in a nuclei template can be called/executed in javascript in format `proto_name()` i.e `http()` , `dns()` , `ssl()` etc
  If we want to execute a specific request of a protocol (ref: see [nuclei-flow-dns](testcases/nuclei-flow-dns-id.yaml)) this can be achieved by either passing
  - index of that request in protocol (ex: `dns(0)`, `dns(1)` etc)
  - id of that request in protocol (ex: `dns("extract-vps")`, `dns("probe-http")` etc)
  For More complex use cases multiple requests of a single protocol can be executed by just specifying their index or id one after another (ex: `dns("extract-vps","1")`)

**2. Iterate Helper Function**
  
  Iterate is a nuclei js helper function which can be used to iterate over any type of value (array,map,string,number) while handling empty / nil values.
  This is addon helper function from nuclei to omit boilerplate code of checking if value is empty or not and then iterating over it
  ```javascript
  iterate(123,{"a":1,"b":2,"c":3})
  // iterate over array with custom separator
  iterate([1,2,3,4,5], " ")
  ```
  **Note:** In above example we used `iterate(template["ssl_subject_cn"],template["ssl_subject_an"])` which removed lot of boilerplate code of checking if value is empty or not and then iterating over it

**3. Set Helper Function**

  When Iterating over a values/array or some other use case we might want to invoke a request with custom/given value and this can be achieved by using `set()` helper function. When invoked/called it adds given variable to template context (global variables) and that value is used during execution of request/protocol. the format of `set()` is `set("variable_name",value)` ex: `set("username","admin")` etc
  ```javascript
    for (let vhost of myArray) {
    set("vhost", vhost);
    http(1)
  }
  ```
  **Note:** In above example we used `set("vhost", vhost)` which added `vhost` to template context (global variables) and then called `http(1)` which used this value in request

**4. Template Context**

  when using `nuclei -jsonl` flag we get lot of data/metadata related to a vulnerability (ex: template details,extracted-values and much more) . A template context is nothing but a map/JSON containing all this data along with internal/unexported data that is only available at runtime (ex: extracted values from previous requests, variables added using `set()` etc). This template context is available in javascript as `template` variable and can be used to access any data from it. ex: `template["ssl_subject_cn"]` , `template["ssl_subject_an"]` etc
  ```javascript
  template["ssl_subject_cn"] // returns value of ssl_subject_cn from template context which is available after executing ssl request 
  template["ptrValue"]  // returns value of ptrValue which was extracted using regex with internal: true
  ```
  Lot of times we don't known what all data is available in template context and this can be easily found by printing it to stdout using `log()` function
  ```javascript
  log(template)
  ```

**5. Log Helper Function**

  It is a nuclei js alternative to `console.log` and this pretty prints map data in readable format
  **Note:** This should be used for debugging purposed only as this prints data to stdout

**6. Dedupe**

  Lot of times just having arrays/slices is not enough and we might need to remove duplicate variables . for example in earlier vhost enumeration we did not remove any duplicates as there is always a chance of duplicate values in `ssl_subject_cn` and `ssl_subject_an` and this can be achieved by using `dedupe()` object. This is nuclei js helper function to abstract away boilerplate code of removing duplicates from array/slice
  ```javascript
  let uniq = new Dedupe(); // create new dedupe object
  uniq.Add(template["ptrValue"]) 
  uniq.Add(template["ssl_subject_cn"]);
  uniq.Add(template["ssl_subject_an"]); 
  log(uniq.Values())
  ```
  And that's it , this automatically converts any slice/array to map and removes duplicates from it and returns a slice/array of unique values

------
> Similar to DSL helper functions . we can either use built in functions available with `Javscript (ECMAScript 5.1)` or use DSL helper functions and its upto user to decide which one to uses