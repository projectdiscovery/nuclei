## jsdocgen

jsdocgen is LLM (OpenAI) based dev tool it takes generated javascript files and annotes them with jsdoc comments using predefined prompt

### Usage

```bash
 ./jsdocgen -h
Usage of ./jsdocgen:
  -dir string
    	directory to process
  -key string
    	openai api key
  -keyfile string
    	openai api key file
```

### Example

```bash
./jsdocgen -dir modules/generated/js/libmysql -keyfile ~/.openai/key
```


### Example Conversion
