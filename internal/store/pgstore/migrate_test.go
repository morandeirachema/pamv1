package pgstore

import (
	"sort"
	"strings"
	"testing"
)

func TestLoadMigrations(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations embedded")
	}

	// Baseline is 0001_init and creates the core tables.
	if ms[0].version != "0001" || ms[0].name != "0001_init.sql" {
		t.Fatalf("first migration = %+v, want 0001_init", ms[0])
	}
	if !strings.Contains(ms[0].sql, "CREATE TABLE") {
		t.Fatal("0001 should contain DDL")
	}

	// Names are strictly ordered and versions unique.
	if !sort.SliceIsSorted(ms, func(i, j int) bool { return ms[i].name < ms[j].name }) {
		t.Fatal("migrations are not ordered by name")
	}
	seen := map[string]bool{}
	for _, m := range ms {
		if seen[m.version] {
			t.Fatalf("duplicate migration version %q", m.version)
		}
		seen[m.version] = true
	}
}
