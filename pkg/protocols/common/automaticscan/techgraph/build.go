package techgraph

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Build walks the templates root and produces the tech-graph artifact.
func Build(root string) (*Graph, error) {
	root = filepath.Clean(root)
	g := &Graph{
		Version:     ArtifactVersion,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Techs:       map[string]*Tech{},
		Synonyms:    map[string]string{},
	}

	infos, hash, parseErr, err := collect(root)
	if err != nil {
		return nil, err
	}
	g.Stats.ParseError = parseErr
	g.SourceHash = fmt.Sprintf("sha256:%x", hash)

	var deferred []templateInfo

	// Pass 1: build tech nodes from authoritative signals (detection anchors,
	// cpe/product, platform). Everything else is deferred so it can be resolved
	// against the fully-built node set in pass 2.
	for _, info := range infos {
		g.Stats.Total++

		if isDetection(info) && isDetectionSeverity(info) {
			id := techID(info.Vendor, info.Product)
			if id != "" {
				g.anchorTech(id, info)
			}
			g.Detection = append(g.Detection, DetectionEntry{ID: info.ID, Tech: id})
			g.Stats.Detection++
			continue
		}
		if _, ok := excludedCategories[info.Category]; ok {
			g.Stats.Excluded++
			continue
		}
		if p, ok := detectPlatform(info); ok {
			g.addDependent(p, info, "platform")
			g.Stats.Dependents++
			g.Stats.DependentsPlat++
			continue
		}
		if id := techID(info.Vendor, info.Product); id != "" {
			g.addDependent(id, info, "cpe")
			g.Stats.Dependents++
			g.Stats.DependentsCPE++
			continue
		}
		deferred = append(deferred, info)
	}

	// Pass 2: resolve deferred templates to a known tech BEFORE considering
	// baseline. Order: directory grouping -> tag -> id token. Only genuinely
	// generic leftovers become baseline; the rest are unmapped (runtime fallback).
	aliasIdx := g.buildAliasIndex()
	for _, info := range deferred {
		if id, ok := g.resolveToken(info.Subdir, aliasIdx); ok {
			g.addDependent(id, info, "dir")
			g.Stats.Dependents++
			g.Stats.DependentsDir++
			continue
		}
		if id, ok := reconcileByTag(g, info, aliasIdx); ok {
			g.addDependent(id, info, "tag")
			g.Stats.Dependents++
			g.Stats.DependentsTag++
			continue
		}
		if id, ok := reconcileByID(g, info, aliasIdx); ok {
			g.addDependent(id, info, "id")
			g.Stats.Dependents++
			g.Stats.DependentsID++
			continue
		}
		if tier, ok := classifyBaseline(info); ok {
			g.Baseline = append(g.Baseline, BaselineEntry{
				ID: info.ID, Category: info.Category, Severity: info.Severity, Tier: tier,
			})
			g.Stats.Baseline++
			continue
		}
		g.Stats.Unmapped++
	}

	// ship validated seed synonyms in the artifact so the runtime selector (which
	// only reads the artifact) can resolve acronyms like aem -> adobe:experience_manager.
	for alias, id := range seedSynonyms {
		if _, ok := g.Techs[id]; ok {
			g.Synonyms[alias] = id
		}
	}

	g.Stats.Techs = len(g.Techs)
	g.sortStable()
	return g, nil
}

// collect walks the tree once and returns parsed infos plus a content hash.
func collect(root string) ([]templateInfo, []byte, int, error) {
	var infos []templateInfo
	var parseErr int
	hasher := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml") {
			return nil
		}
		info, ok := extractTemplate(path, root)
		if !ok {
			parseErr++
			return nil
		}
		fmt.Fprintf(hasher, "%s|%s|%s|%s\n", info.ID, info.Vendor, info.Product, info.CPE)
		infos = append(infos, info)
		return nil
	})
	if err != nil {
		return nil, nil, 0, err
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
	return infos, hasher.Sum(nil), parseErr, nil
}

// anchorTech creates/updates a tech node's metadata without adding a fireable
// template (used by detector templates that define a tech).
func (g *Graph) anchorTech(id string, info templateInfo) *Tech {
	tech, ok := g.Techs[id]
	if !ok {
		tech = &Tech{ID: id, Vendor: normToken(info.Vendor), Product: normToken(info.Product), CPE: info.CPE}
		g.Techs[id] = tech
	}
	if tech.CPE == "" && info.CPE != "" {
		tech.CPE = info.CPE
	}
	mergeAliases(tech, aliasesFor(info.Vendor, info.Product, info.Tags))
	for _, a := range tech.Aliases {
		if existing, ok := g.Synonyms[a]; !ok || existing == id {
			g.Synonyms[a] = id
		}
	}
	return tech
}

// addDependent registers a fireable template under its canonical tech.
//
// Only "cpe" attachments contribute aliases (the template's own vendor/product
// genuinely define the tech). Platform/dir/tag/id attachments must NOT pollute
// the node's aliases with the sub-product's tokens (e.g. a wp-plugin's name must
// not become a wordpress alias), which would corrupt reconciliation.
func (g *Graph) addDependent(id string, info templateInfo, source string) {
	var tech *Tech
	if source == "cpe" {
		tech = g.anchorTech(id, info)
	} else {
		tech = g.ensureTech(id, info)
	}
	ref := TemplateRef{ID: info.ID, Category: info.Category, Severity: info.Severity, Source: source}
	if source == "platform" || source == "dir" {
		ref.Product = normToken(info.Product)
	}
	tech.Templates = append(tech.Templates, ref)
}

// ensureTech returns an existing node, or creates a bare one without merging the
// template's aliases (used for non-cpe attachments).
func (g *Graph) ensureTech(id string, info templateInfo) *Tech {
	if tech, ok := g.Techs[id]; ok {
		return tech
	}
	vendor, product := "", ""
	if v, p, ok := splitTechID(id); ok {
		vendor, product = v, p
	}
	tech := &Tech{ID: id, Vendor: vendor, Product: product}
	g.Techs[id] = tech
	return tech
}

// splitTechID reverses techID for bare node creation.
func splitTechID(id string) (vendor, product string, ok bool) {
	if i := strings.IndexByte(id, ':'); i > 0 {
		return id[:i], id[i+1:], true
	}
	return "", id, true
}

// buildAliasIndex maps a single alias/product token to a unique tech id. Tokens
// that resolve to more than one tech, are too short, or are generic are dropped
// so tag reconciliation stays conservative.
func (g *Graph) buildAliasIndex() map[string]string {
	counts := map[string]map[string]struct{}{}
	add := func(tok, id string) {
		tok = normToken(tok)
		if len(tok) < 5 || genericTokens[tok] {
			return
		}
		if counts[tok] == nil {
			counts[tok] = map[string]struct{}{}
		}
		counts[tok][id] = struct{}{}
	}
	for id, tech := range g.Techs {
		add(id, id)
		add(tech.Product, id)
		for _, a := range tech.Aliases {
			add(a, id)
		}
	}
	idx := map[string]string{}
	for tok, ids := range counts {
		if len(ids) == 1 {
			for id := range ids {
				idx[tok] = id
			}
		}
	}
	return idx
}

// resolveToken maps a single token to a tech id via the seed synonym table
// first (validated against existing nodes), then the alias index.
func (g *Graph) resolveToken(tok string, idx map[string]string) (string, bool) {
	tok = normToken(tok)
	if tok == "" || genericTokens[tok] {
		return "", false
	}
	if id, ok := seedSynonyms[tok]; ok {
		if _, exists := g.Techs[id]; exists {
			return id, true
		}
	}
	if id, ok := idx[tok]; ok {
		return id, true
	}
	return "", false
}

// reconcileByTag attaches a product-less template to a known tech when its tags
// resolve to exactly one unique tech node.
func reconcileByTag(g *Graph, info templateInfo, idx map[string]string) (string, bool) {
	matches := map[string]struct{}{}
	for _, tag := range info.Tags {
		if id, ok := g.resolveToken(tag, idx); ok {
			matches[id] = struct{}{}
		}
	}
	if len(matches) == 1 {
		for id := range matches {
			return id, true
		}
	}
	return "", false
}

// reconcileByID attaches a template when its id tokens resolve to exactly one
// unique tech node (e.g. "aem-jcr-exposure" -> adobe:experience_manager).
//
// This is the riskiest signal (id tokens are common English words), so it is
// guarded: a token must be >=6 chars AND also appear in the template name, which
// requires the product to be the template's actual subject rather than an
// incidental id suffix like "-dashboard"/"-gateway".
func reconcileByID(g *Graph, info templateInfo, idx map[string]string) (string, bool) {
	name := strings.ToLower(info.Name)
	matches := map[string]struct{}{}
	for _, tok := range strings.Split(strings.ToLower(info.ID), "-") {
		if len(tok) < 6 || !strings.Contains(name, tok) {
			continue
		}
		if id, ok := g.resolveToken(tok, idx); ok {
			matches[id] = struct{}{}
		}
	}
	if len(matches) == 1 {
		for id := range matches {
			return id, true
		}
	}
	return "", false
}

func mergeAliases(tech *Tech, aliases []string) {
	have := map[string]struct{}{}
	for _, a := range tech.Aliases {
		have[a] = struct{}{}
	}
	for _, a := range aliases {
		if a == "" {
			continue
		}
		if _, ok := have[a]; ok {
			continue
		}
		have[a] = struct{}{}
		tech.Aliases = append(tech.Aliases, a)
	}
}

func (g *Graph) sortStable() {
	for _, tech := range g.Techs {
		sort.Strings(tech.Aliases)
		sort.Slice(tech.Templates, func(i, j int) bool {
			return tech.Templates[i].ID < tech.Templates[j].ID
		})
	}
	sort.Slice(g.Baseline, func(i, j int) bool { return g.Baseline[i].ID < g.Baseline[j].ID })
	sort.Slice(g.Detection, func(i, j int) bool { return g.Detection[i].ID < g.Detection[j].ID })
}

// WriteFile serialises the graph as indented JSON.
func (g *Graph) WriteFile(path string) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func skipDir(name string) bool {
	switch name {
	case ".git", ".github", "helpers", "profiles", "workflows":
		return true
	}
	return false
}
