package main

import (
	"strings"
	"testing"
)

// TestArchgenProducesDiagrams runs the three generators against the real module
// and checks each emits its diagram with content derived from the current code
// (a package node, an ER relationship, a known route). This guards the generator
// itself; CI separately fails if the committed doc is stale.
func TestArchgenProducesDiagrams(t *testing.T) {
	root, module, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := writePackageGraph(&b, root, module); err != nil {
		t.Fatal(err)
	}
	if err := writeDataModel(&b, root); err != nil {
		t.Fatal(err)
	}
	if err := writeRouteMap(&b, root); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"flowchart LR",
		"n_api[api]",
		"n_proxy --> n_vault", // proxy decrypts JIT via vault
		"erDiagram",
		"Credential ||--o{ Checkout", // inferred FK relationship
		"| GET | `/api/me` |",        // route map picked up the new endpoint
	} {
		if !strings.Contains(out, want) {
			t.Errorf("generated architecture output is missing %q", want)
		}
	}
}
