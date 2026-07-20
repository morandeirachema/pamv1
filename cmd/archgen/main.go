// Command archgen regenerates docs/ARCHITECTURE-DIAGRAMS.md from the source, so
// the architecture diagrams cannot drift from the code. It derives three views
// directly from the Go sources:
//
//   - a package dependency graph (from each package's intra-module imports),
//   - the domain data model as an ER diagram (from the structs in internal/store),
//   - the REST route → capability map (from internal/api/server.go's mux wiring).
//
// Output is deterministic (everything is sorted, no timestamps), so CI can run
// `go run ./cmd/archgen` and fail on any diff — that is what keeps the diagrams
// current on every change.
//
//go:generate go run .
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func main() {
	root, module, err := moduleRoot()
	if err != nil {
		fatal(err)
	}
	var b strings.Builder
	writeHeader(&b)
	if err := writePackageGraph(&b, root, module); err != nil {
		fatal(err)
	}
	if err := writeDataModel(&b, root); err != nil {
		fatal(err)
	}
	if err := writeRouteMap(&b, root); err != nil {
		fatal(err)
	}
	out := filepath.Join(root, "docs", "ARCHITECTURE-DIAGRAMS.md")
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fatal(err)
	}
	rel, _ := filepath.Rel(root, out)
	fmt.Println("wrote", rel)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "archgen:", err)
	os.Exit(1)
}

// moduleRoot walks up from the working directory to the directory holding go.mod
// and returns it plus the module path, so archgen works from any CWD.
func moduleRoot() (root, module string, err error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	for {
		gomod := filepath.Join(dir, "go.mod")
		if data, e := os.ReadFile(gomod); e == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "module ") {
					return dir, strings.TrimSpace(strings.TrimPrefix(line, "module ")), nil
				}
			}
			return dir, "", fmt.Errorf("no module line in go.mod")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", fmt.Errorf("go.mod not found from working directory")
		}
		dir = parent
	}
}

func writeHeader(b *strings.Builder) {
	b.WriteString(`# pamv1 — Architecture Diagrams (generated)

> **Do not edit by hand.** This file is regenerated from the source by
> ` + "`go run ./cmd/archgen`" + ` (or ` + "`go generate ./...`" + `). CI runs the
> generator and fails if the committed copy is stale, so these diagrams stay in
> step with the code on every change. Conceptual flows (trust zones, the JIT
> proxy sequence, deployment) live in the hand-authored
> [High-Level Architecture](ARCHITECTURE-HIGH-LEVEL.md) and
> [Low-Level Architecture](ARCHITECTURE-LOW-LEVEL.md).

Rendering: these are [Mermaid](https://mermaid.js.org/) diagrams; GitHub renders
them inline.

`)
}

// --- package dependency graph -------------------------------------------------

// pkgLayer groups packages into architectural layers for readable subgraphs. A
// package not listed here falls into the "Other" bucket, so new packages still
// appear (just ungrouped) — the edges are always derived from real imports.
var pkgLayer = []struct {
	name string
	pkgs []string
}{
	{"Entry point", []string{"pam-server", "archgen"}},
	{"Interface", []string{"api", "web", "proxy"}},
	{"Identity & authz", []string{"auth", "oidc", "mfa"}},
	{"Secrets", []string{"vault", "shamir"}},
	{"Persistence", []string{"store", "memstore", "pgstore", "storetest"}},
	{"Connectors", []string{"winrm", "guacd", "rotate", "discovery"}},
	{"Agent broker", []string{"broker", "policy", "agentid", "auditchain", "mcp"}},
	{"Platform", []string{"config", "logging", "metrics", "alert", "session", "maint"}},
}

func layerOf(pkg string) string {
	for _, l := range pkgLayer {
		for _, p := range l.pkgs {
			if p == pkg {
				return l.name
			}
		}
	}
	return "Other"
}

// writePackageGraph parses every package under internal/ and cmd/ and emits a
// Mermaid flowchart of the intra-module import edges, grouped by layer.
func writePackageGraph(b *strings.Builder, root, module string) error {
	dirs, err := packageDirs(root)
	if err != nil {
		return err
	}
	nodes := map[string]bool{}
	edges := map[string]bool{} // "from|to"
	for _, dir := range dirs {
		short := shortName(dir)
		nodes[short] = true
		imps, err := packageImports(filepath.Join(root, dir))
		if err != nil {
			return err
		}
		for _, imp := range imps {
			if !strings.HasPrefix(imp, module+"/") {
				continue // external dependency: out of scope for the internal graph
			}
			to := shortName(strings.TrimPrefix(imp, module+"/"))
			if to == short {
				continue
			}
			nodes[to] = true
			edges[short+"|"+to] = true
		}
	}

	b.WriteString("## 1. Package dependency graph\n\n")
	b.WriteString("Every Go package in the module and the imports between them. Arrows point from a package to the packages it imports.\n\n")
	b.WriteString("```mermaid\nflowchart LR\n")

	// Emit nodes inside per-layer subgraphs (deterministic order).
	grouped := map[string][]string{}
	for n := range nodes {
		grouped[layerOf(n)] = append(grouped[layerOf(n)], n)
	}
	order := make([]string, 0, len(pkgLayer)+1)
	for _, l := range pkgLayer {
		order = append(order, l.name)
	}
	order = append(order, "Other")
	for _, layer := range order {
		ns := grouped[layer]
		if len(ns) == 0 {
			continue
		}
		sort.Strings(ns)
		fmt.Fprintf(b, "  subgraph %s[%q]\n", nodeID(layer), layer)
		for _, n := range ns {
			fmt.Fprintf(b, "    %s[%s]\n", nodeID(n), n)
		}
		b.WriteString("  end\n")
	}

	es := make([]string, 0, len(edges))
	for e := range edges {
		es = append(es, e)
	}
	sort.Strings(es)
	for _, e := range es {
		parts := strings.SplitN(e, "|", 2)
		fmt.Fprintf(b, "  %s --> %s\n", nodeID(parts[0]), nodeID(parts[1]))
	}
	b.WriteString("```\n\n")
	return nil
}

// packageDirs returns the module-relative directories of every Go package under
// internal/ and cmd/, sorted.
func packageDirs(root string) ([]string, error) {
	var dirs []string
	for _, base := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, base), func(path string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			hasGo, e := dirHasGo(path)
			if e != nil {
				return e
			}
			if hasGo {
				rel, _ := filepath.Rel(root, path)
				dirs = append(dirs, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

func dirHasGo(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			return true, nil
		}
	}
	return false, nil
}

// packageImports returns the unique import paths of the non-test Go files in dir.
func packageImports(dir string) ([]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, imp := range file.Imports {
				seen[strings.Trim(imp.Path.Value, `"`)] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out, nil
}

// shortName is the last path element (e.g. "internal/store" -> "store",
// "cmd/pam-server" -> "pam-server").
func shortName(rel string) string {
	rel = strings.TrimSuffix(rel, "/")
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

var nonID = regexp.MustCompile(`[^A-Za-z0-9_]`)

func nodeID(s string) string { return "n_" + nonID.ReplaceAllString(s, "_") }

// --- data model (ER) ----------------------------------------------------------

// writeDataModel emits a Mermaid ER diagram of the domain structs declared in
// internal/store/store.go, inferring relationships from <Entity>ID fields.
func writeDataModel(b *strings.Builder, root string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, "internal", "store", "store.go"), nil, 0)
	if err != nil {
		return err
	}
	type field struct{ typ, name string }
	entities := map[string][]field{}
	var names []string
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || !ts.Name.IsExported() {
				continue
			}
			var fields []field
			for _, f := range st.Fields.List {
				if len(f.Names) == 0 || !f.Names[0].IsExported() {
					continue
				}
				if f.Tag != nil && strings.Contains(f.Tag.Value, `json:"-"`) {
					continue // never-serialized (e.g. SecretEnc, TokenHash)
				}
				fields = append(fields, field{typ: mermaidType(f.Type), name: f.Names[0].Name})
			}
			if len(fields) > 0 {
				entities[ts.Name.Name] = fields
				names = append(names, ts.Name.Name)
			}
		}
	}
	sort.Strings(names)

	b.WriteString("## 2. Domain data model\n\n")
	b.WriteString("Entities are the exported structs in `internal/store/store.go` (never-serialized fields such as `SecretEnc`/`TokenHash` are omitted). Relationships are inferred from `<Entity>ID` foreign keys.\n\n")
	b.WriteString("```mermaid\nerDiagram\n")
	for _, name := range names {
		fmt.Fprintf(b, "  %s {\n", name)
		for _, f := range entities[name] {
			fmt.Fprintf(b, "    %s %s\n", f.typ, f.name)
		}
		b.WriteString("  }\n")
	}
	// Relationships: a field named <X>ID whose <X> is another entity.
	var rels []string
	for _, name := range names {
		for _, f := range entities[name] {
			if !strings.HasSuffix(f.name, "ID") || f.name == "ID" {
				continue
			}
			base := strings.TrimSuffix(f.name, "ID")
			if _, ok := entities[base]; ok {
				rels = append(rels, fmt.Sprintf("  %s ||--o{ %s : %q", base, name, "has"))
			}
		}
	}
	sort.Strings(rels)
	for _, r := range rels {
		b.WriteString(r + "\n")
	}
	b.WriteString("```\n\n")
	return nil
}

// mermaidType renders a Go type as a Mermaid-safe attribute type (alphanumerics
// and underscores only).
func mermaidType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "ptr_" + mermaidType(t.X)
	case *ast.SelectorExpr:
		return mermaidType(t.X) + "_" + t.Sel.Name
	case *ast.ArrayType:
		return "arr_" + mermaidType(t.Elt)
	case *ast.MapType:
		return "map_" + mermaidType(t.Key) + "_" + mermaidType(t.Value)
	default:
		return "value"
	}
}

// --- REST route map -----------------------------------------------------------

var (
	reRoute = regexp.MustCompile(`s\.mux\.Handle(?:Func)?\("([A-Z]+) ([^"]+)",\s*(.*)$`)
	reCap   = regexp.MustCompile(`auth\.Cap(\w+)`)
)

// writeRouteMap parses the mux wiring in internal/api/server.go into a table of
// method, path, and the capability (or guard) each route enforces.
func writeRouteMap(b *strings.Builder, root string) error {
	data, err := os.ReadFile(filepath.Join(root, "internal", "api", "server.go"))
	if err != nil {
		return err
	}
	type route struct{ method, path, guard string }
	var routes []route
	for _, line := range strings.Split(string(data), "\n") {
		m := reRoute.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		guard := "public"
		if c := reCap.FindStringSubmatch(m[3]); c != nil {
			guard = "Cap" + c[1]
		} else if strings.Contains(m[3], "authenticated(") {
			guard = "authenticated"
		} else if strings.Contains(m[3], "rateLimit(") {
			guard = "public (rate-limited)"
		} else if strings.Contains(m[3], "rdpTunnel") {
			guard = "token (query)"
		}
		routes = append(routes, route{m[1], m[2], guard})
	}
	sort.SliceStable(routes, func(i, j int) bool {
		if routes[i].path != routes[j].path {
			return routes[i].path < routes[j].path
		}
		return routes[i].method < routes[j].method
	})

	b.WriteString("## 3. REST API surface\n\n")
	fmt.Fprintf(b, "The %d routes registered on the API mux, with the capability or guard each enforces (see `internal/auth` for the role → capability matrix).\n\n", len(routes))
	b.WriteString("| Method | Path | Guard |\n|---|---|---|\n")
	for _, r := range routes {
		fmt.Fprintf(b, "| %s | `%s` | %s |\n", r.method, r.path, r.guard)
	}
	b.WriteString("\n")
	return nil
}
