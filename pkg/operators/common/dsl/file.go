package dsl

import (
	"io"
	"os"
	"sync"

	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
	unitutils "github.com/projectdiscovery/utils/unit"
)

const (
	// maxFileHelperSize is the maximum number of bytes file() will read.
	// Matches the default HTTP response read limit.
	maxFileHelperSize = int64(10 * unitutils.Mega)
)

// FileLoadContext carries the sandbox inputs required by the file() DSL helper.
// It must be installed with WithFileLoadContext for the duration of template
// evaluation on a worker goroutine.
type FileLoadContext struct {
	Options      *types.Options
	TemplatePath string
	Catalog      catalog.Catalog

	cache sync.Map // abs/logical path -> string contents
}

type fileLoadFrame struct {
	ctx  *FileLoadContext
	prev *fileLoadFrame
}

var fileLoadByGoid sync.Map // uint64 -> *fileLoadFrame

// WithFileLoadContext installs ctx for the calling goroutine, runs fn, then
// restores the previous context (if any). Nested calls are supported.
func WithFileLoadContext(ctx *FileLoadContext, fn func()) {
	if fn == nil {
		return
	}
	id := goid()
	var prev *fileLoadFrame
	if existing, ok := fileLoadByGoid.Load(id); ok {
		prev = existing.(*fileLoadFrame)
	}
	fileLoadByGoid.Store(id, &fileLoadFrame{ctx: ctx, prev: prev})
	defer func() {
		if prev == nil {
			fileLoadByGoid.Delete(id)
		} else {
			fileLoadByGoid.Store(id, prev)
		}
	}()
	fn()
}

func currentFileLoadContext() *FileLoadContext {
	if v, ok := fileLoadByGoid.Load(goid()); ok {
		if frame := v.(*fileLoadFrame); frame != nil {
			return frame.ctx
		}
	}
	return nil
}

func registerFileHelper() {
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("file", []string{
		"(path string) string",
	}, false, fileHelper))
}

func fileHelper(args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, dsl.ErrInvalidDslFunction
	}
	path := types.ToString(args[0])
	if path == "" {
		return nil, errkit.New("file(): path must not be empty")
	}

	ctx := currentFileLoadContext()
	if ctx == nil || ctx.Options == nil {
		return nil, errkit.New("file(): no template sandbox context (only available during template execution)")
	}

	if cached, ok := ctx.cache.Load(path); ok {
		return cached, nil
	}

	contents, err := ctx.readFile(path)
	if err != nil {
		return nil, err
	}
	ctx.cache.Store(path, contents)
	return contents, nil
}

func (ctx *FileLoadContext) readFile(path string) (string, error) {
	reader, err := ctx.Options.LoadHelperFile(path, ctx.TemplatePath, ctx.Catalog)
	if err != nil {
		return "", errkit.Wrapf(err, "file(): could not load %q", path)
	}
	defer func() { _ = reader.Close() }()

	if file, ok := reader.(*os.File); ok {
		info, statErr := file.Stat()
		if statErr != nil {
			return "", errkit.Wrapf(statErr, "file(): could not stat %q", path)
		}
		if !info.Mode().IsRegular() {
			return "", errkit.Newf("file(): %q is not a regular file", path)
		}
		if info.Size() > maxFileHelperSize {
			return "", errkit.Newf("file(): %q exceeds maximum size of %d bytes", path, maxFileHelperSize)
		}
	}

	limited := io.LimitReader(reader, maxFileHelperSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return "", errkit.Wrapf(err, "file(): could not read %q", path)
	}
	if int64(len(data)) > maxFileHelperSize {
		return "", errkit.Newf("file(): %q exceeds maximum size of %d bytes", path, maxFileHelperSize)
	}

	// Go strings are binary-safe; keep opaque bytes for payload use.
	return string(data), nil
}
