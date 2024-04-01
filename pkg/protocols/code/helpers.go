package code

import (
	goruntime "runtime"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
	osutils "github.com/projectdiscovery/utils/os"
)

// registerPreConditionFunctions registers the pre-condition functions
func registerPreConditionFunctions(runtime *goja.Runtime) error {
	// Note: the only reason we are not using forloop to generate these functions is because
	// 'scrapefuncs' uses this function to find all dsl helper functions  and document them.

	// === OS ===
	err := gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "OS",
		Signatures: []string{
			"OS() string",
		},
		Description: "OS returns the current OS",
		FuncDecl: func() string {
			return goruntime.GOOS
		},
	})
	if err != nil {
		return err
	}

	// IsLinux checks if the current OS is Linux
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsLinux",
		Signatures: []string{
			"IsLinux() bool",
		},
		Description: "IsLinux checks if the current OS is Linux",
		FuncDecl: func() bool {
			return osutils.IsLinux()
		},
	})
	if err != nil {
		return err
	}

	// IsWindows checks if the current OS is Windows
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsWindows",
		Signatures: []string{
			"IsWindows() bool",
		},
		Description: "IsWindows checks if the current OS is Windows",
		FuncDecl: func() bool {
			return osutils.IsWindows()
		},
	})
	if err != nil {
		return err
	}

	// IsOSX checks if the current OS is OSX
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsOSX",
		Signatures: []string{
			"IsOSX() bool",
		},
		Description: "IsOSX checks if the current OS is OSX",

		FuncDecl: func() bool {
			return osutils.IsOSX()
		},
	})
	if err != nil {
		return err
	}

	// IsAndroid checks if the current OS is Android
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsAndroid",
		Signatures: []string{
			"IsAndroid() bool",
		},
		Description: "IsAndroid checks if the current OS is Android",
		FuncDecl: func() bool {
			return osutils.IsAndroid()
		},
	})
	if err != nil {
		return err
	}

	// IsIOS checks if the current OS is IOS
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsIOS",
		Signatures: []string{
			"IsIOS() bool",
		},
		Description: "IsIOS checks if the current OS is IOS",
		FuncDecl: func() bool {
			return osutils.IsIOS()
		},
	})
	if err != nil {
		return err
	}

	// IsJS checks if the current OS is JS
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsJS",
		Signatures: []string{
			"IsJS() bool",
		},
		Description: "IsJS checks if the current OS is JS",
		FuncDecl: func() bool {
			return osutils.IsJS()
		},
	})
	if err != nil {
		return err
	}

	// IsFreeBSD checks if the current OS is FreeBSD
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsFreeBSD",
		Signatures: []string{
			"IsFreeBSD() bool",
		},
		Description: "IsFreeBSD checks if the current OS is FreeBSD",
		FuncDecl: func() bool {
			return osutils.IsFreeBSD()
		},
	})
	if err != nil {
		return err
	}

	// IsOpenBSD checks if the current OS is OpenBSD
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsOpenBSD",
		Signatures: []string{
			"IsOpenBSD() bool",
		},
		Description: "IsOpenBSD checks if the current OS is OpenBSD",
		FuncDecl: func() bool {
			return osutils.IsOpenBSD()
		},
	})
	if err != nil {
		return err
	}

	// IsSolaris checks if the current OS is Solaris
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsSolaris",
		Signatures: []string{
			"IsSolaris() bool",
		},
		Description: "IsSolaris checks if the current OS is Solaris",
		FuncDecl: func() bool {
			return osutils.IsSolaris()
		},
	})
	if err != nil {
		return err
	}

	// === Arch ===
	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "Arch",
		Signatures: []string{
			"Arch() string",
		},
		Description: "Arch returns the current architecture",
		FuncDecl: func() string {
			return goruntime.GOARCH
		},
	})
	if err != nil {
		return err
	}

	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "Is386",
		Signatures: []string{
			"Is386() bool",
		},
		Description: "Is386 checks if the current architecture is 386",
		FuncDecl: func() bool {
			return osutils.Is386()
		},
	})
	if err != nil {
		return err
	}

	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsAmd64",
		Signatures: []string{
			"IsAmd64() bool",
		},
		Description: "IsAmd64 checks if the current architecture is Amd64",
		FuncDecl: func() bool {
			return osutils.IsAmd64()
		},
	})
	if err != nil {
		return err
	}

	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsARM",
		Signatures: []string{
			"IsARM() bool",
		},
		Description: "IsArm checks if the current architecture is Arm",
		FuncDecl: func() bool {
			return osutils.IsARM()
		},
	})
	if err != nil {
		return err
	}

	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsARM64",
		Signatures: []string{
			"IsARM64() bool",
		},
		Description: "IsArm64 checks if the current architecture is Arm64",
		FuncDecl: func() bool {
			return osutils.IsARM64()
		},
	})
	if err != nil {
		return err
	}

	err = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name: "IsWasm",
		Signatures: []string{
			"IsWasm() bool",
		},
		Description: "IsWasm checks if the current architecture is Wasm",
		FuncDecl: func() bool {
			return osutils.IsWasm()
		},
	})
	if err != nil {
		return err
	}

	return nil
}

func cleanUpPreConditionFunctions(runtime *goja.Runtime) {
	_ = runtime.GlobalObject().Delete("OS")
	_ = runtime.GlobalObject().Delete("IsLinux")
	_ = runtime.GlobalObject().Delete("IsWindows")
	_ = runtime.GlobalObject().Delete("IsOSX")
	_ = runtime.GlobalObject().Delete("IsAndroid")
	_ = runtime.GlobalObject().Delete("IsIOS")
	_ = runtime.GlobalObject().Delete("IsJS")
	_ = runtime.GlobalObject().Delete("IsFreeBSD")
	_ = runtime.GlobalObject().Delete("IsOpenBSD")
	_ = runtime.GlobalObject().Delete("IsSolaris")
	_ = runtime.GlobalObject().Delete("Arch")
	_ = runtime.GlobalObject().Delete("Is386")
	_ = runtime.GlobalObject().Delete("IsAmd64")
	_ = runtime.GlobalObject().Delete("IsARM")
	_ = runtime.GlobalObject().Delete("IsARM64")
	_ = runtime.GlobalObject().Delete("IsWasm")
}
