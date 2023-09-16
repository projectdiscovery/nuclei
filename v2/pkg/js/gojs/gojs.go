package gojs

import (
	"sync"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/require"
)

type Objects map[string]interface{}

type Runtime interface {
	Set(string, interface{}) error
}

type Object interface {
	Set(string, interface{})
	Get(string) interface{}
}

type Module interface {
	Name() string
	Set(objects Objects) Module
	Enable(Runtime)
	Register() Module
}

type GojaModule struct {
	name string
	sets map[string]interface{}
	once sync.Once
}

func NewGojaModule(name string) Module {
	return &GojaModule{
		name: name,
		sets: make(map[string]interface{}),
	}
}

func (p *GojaModule) String() string {
	return p.name
}

func (p *GojaModule) Name() string {
	return p.name
}

func (p *GojaModule) Set(objects Objects) Module {

	for k, v := range objects {
		p.sets[k] = v
	}

	return p
}

func (p *GojaModule) Require(runtime *goja.Runtime, module *goja.Object) {

	o := module.Get("exports").(*goja.Object)

	for k, v := range p.sets {
		_ = o.Set(k, v)
	}
}

func (p *GojaModule) Enable(runtime Runtime) {
	_ = runtime.Set(p.Name(), require.Require(runtime.(*goja.Runtime), p.Name()))
}

func (p *GojaModule) Register() Module {
	p.once.Do(func() {
		require.RegisterNativeModule(p.Name(), p.Require)
	})

	return p
}
