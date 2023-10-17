## Using Nuclei as Library

Nuclei was primarily built as a CLI tool, but with increasing choice of users wanting to use nuclei as library in their own automation, we have added a simplified Library/SDK of nuclei in v3

### Installation

To add nuclei as a library to your go project, you can use the following command:

```bash
go get -u github.com/projectdiscovery/nuclei/v3/lib
```

Or add below import to your go file and let IDE handle the rest:

```go
import nuclei "github.com/projectdiscovery/nuclei/v3/lib"
```

## Basic Example of using Nuclei Library/SDK

```go
// create nuclei engine with options
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{Severity: "critical"}), // run critical severity templates only
	)
	if err != nil {
		panic(err)
	}
	// load targets and optionally probe non http/https targets
	ne.LoadTargets([]string{"scanme.sh"}, false)
	err = ne.ExecuteWithCallback(nil)
	if err != nil {
		panic(err)
	}
	defer ne.Close()
```

## Advanced Example of using Nuclei Library/SDK

For Various use cases like batching etc you might want to run nuclei in goroutines this can be done by using `nuclei.NewThreadSafeNucleiEngine`

```go
// create nuclei engine with options
	ne, err := nuclei.NewThreadSafeNucleiEngine()
	if err != nil{
        panic(err)
    }
	// setup waitgroup to handle concurrency
	wg := &sync.WaitGroup{}

	// scan 1 = run dns templates on scanme.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "http"}))
		if err != nil {
            panic(err)
        }
	}()

	// scan 2 = run http templates on honey.scanme.sh
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = ne.ExecuteNucleiWithOpts([]string{"honey.scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}))
		if err != nil {
            panic(err)
        }
	}()

	// wait for all scans to finish
	wg.Wait()
	defer ne.Close()
```

## More Documentation

For complete documentation of nuclei library, please refer to [godoc](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/lib) which contains all available options and methods.



### Note

| :exclamation:  **Disclaimer**  |
|---------------------------------|
| **This project is in active development**. Expect breaking changes with releases. Review the release changelog before updating. |
| This project was primarily built to be used as a standalone CLI tool. **Running nuclei as a service may pose security risks.** It's recommended to use with caution and additional security measures. |