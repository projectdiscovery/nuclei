## devtools

devtools contains tools and scripts to automate booring tasks related to javascript layer/ packages.

### bindgen

[bindgen](./bindgen/README.md) is a tool that automatically generated bindings for native go packages with 'goja'


### scrapefuncs

[scrapefuncs](./scrapefuncs/README.md) is a tool to scrapes all helper functions exposed in javascript with help of go/ast and generates a js file with jsdoc comments using LLM (OpenAI)


### Generating API Reference (aka static site using javascript files using jsdoc)

```console
jsdoc -R [Homepage.md] -r -d api_reference -t [optional: jsdoc theme to use] generated/js
```

generated static site will be available at `api_reference/` directory and can be verified using simplehttpserver

```console
simplehttpserver
```

and then open `http://localhost:8000/` in browser


### Notes

we currently use [clean-jsdoc-theme](https://www.npmjs.com/package/clean-jsdoc-theme) demo at [sample-jsproto-docs/](https://projectdiscovery.github.io/js-proto-docs/)