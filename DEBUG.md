## Debugging Nuclei

While Adding new features or fixing bugs or writing new templates to properly understand the behavior of that component, it is essential to understand what debugging options are available in nuclei. This guide lists all the debugging options available in nuclei.

### Template related debugging

- `-debug` flag

When this flag is provided, nuclei will print all requests that are being sent by nuclei to the target as well as the response received from the target.

- `-debug-req` flag

When this flag is provided, nuclei will print all requests that are being sent by nuclei to the target.

- `-debug-resp` flag

When this flag is provided, nuclei will  print all responses that are being received by nuclei from the target.

- `-ldf` flag

When this flag is provided, nuclei will print the list of all helper functions available in this release of nuclei and exit.

- `-svd` flag

When this flag is provided, nuclei will print all `variables` pre and post execution of a request for a template. This is useful to understand what variables are available for a template and what values they have.

- `-elog = errors.txt` flag

When this flag is provided, nuclei will log all errors to the file specified. This is helpful when running large scans.



### Environment Variable Switches

Nuclei was built with some environment variables in mind to help with debugging. These environment variables can be set to enable debugging of a particular component/functionality for nuclei.

| Environment Variable             | Description                                              |
| -------------------------------- | -------------------------------------------------------- |
| `DEBUG=true`                     | Enables Printing Stack Traces for all errors             |
| `SHOW_DSL_ERRORS=true`           | Enables Printing DSL Errors (that are hidden by default) |
| `HIDE_TEMPLATE_SIG_WARNING=true` | Hides Template Signature Verification Warnings           |
| `NUCLEI_LOG_ALL=true`            | Log All Events that were skipped in verbose mode         |



