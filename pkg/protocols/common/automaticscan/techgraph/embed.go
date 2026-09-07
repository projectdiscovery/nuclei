package techgraph

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// embeddedGraph is the prebuilt tech-graph artifact shipped with nuclei. Run the
// techgraph-gen command to regenerate it against a nuclei-templates checkout.
//
//go:embed tech-graph.json
var embeddedGraph []byte

//go:embed visualizer.html
var visualizerHTML string

// Embedded returns the tech-graph artifact compiled into the binary.
func Embedded() (*Graph, error) {
	g := &Graph{}
	if err := json.Unmarshal(embeddedGraph, g); err != nil {
		return nil, err
	}
	return g, nil
}

// EmbeddedRaw returns the raw embedded artifact bytes.
func EmbeddedRaw() []byte { return embeddedGraph }

// StandaloneHTML returns the visualizer with the given graph inlined, so it can
// be opened directly in a browser without a server or sidecar file.
func StandaloneHTML(g *Graph) (string, error) {
	data, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	inject := "<script>window.__TECHGRAPH__=" + string(data) + ";</script>\n</head>"
	return strings.Replace(visualizerHTML, "</head>", inject, 1), nil
}
