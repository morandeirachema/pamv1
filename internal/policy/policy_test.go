package policy

import (
	"strings"
	"testing"
	"time"
)

// mustLoad parses YAML or fails the test.
func mustLoad(t *testing.T, y string) *Engine {
	t.Helper()
	e, err := Load(strings.NewReader(y))
	if err != nil {
		t.Fatalf("Load: %v\npolicy:\n%s", err, y)
	}
	return e
}

// TestEvaluate covers the operators, AND logic, first-match ordering, implicit
// deny, match-all (missing tool), and scope templating (success + fail-closed).
func TestEvaluate(t *testing.T) {
	const p = `
rules:
  - id: no-delete
    tool: delete_repo
    effect: deny
    reason: destructive
  - id: read-free
    tool: get_repo
    effect: allow
    scope: "repo:{repo}:read"
    ttl_seconds: 60
  - id: merge-safe
    tool: merge_pr
    when: { args.base: { in: [develop, staging] } }
    effect: allow
    scope: "repo:{repo}:write"
    ttl_seconds: 30
  - id: merge-human
    tool: merge_pr
    effect: require_approval
    approvers: [platform-team]
    scope: "repo:{repo}:write"
  - id: block-prod-repo
    tool: tag
    when: { args.repo: { not_in: [acme/payments] } }
    effect: allow
    scope: "repo:{repo}:tag"
  - id: global-audit-note
    effect: allow
`
	e := mustLoad(t, p)

	tests := []struct {
		name       string
		tool       string
		args       map[string]any
		wantRule   string
		wantEffect Effect
		wantScope  string
		wantTTL    time.Duration
	}{
		{"deny wins", "delete_repo", map[string]any{"repo": "acme/x"}, "no-delete", EffectDeny, "", 0},
		{"read renders scope", "get_repo", map[string]any{"repo": "acme/x"}, "read-free", EffectAllow, "repo:acme/x:read", 60 * time.Second},
		{"in matches safe branch", "merge_pr", map[string]any{"repo": "acme/x", "base": "develop"}, "merge-safe", EffectAllow, "repo:acme/x:write", 30 * time.Second},
		{"first-match falls through to approval", "merge_pr", map[string]any{"repo": "acme/x", "base": "main"}, "merge-human", EffectRequireApproval, "repo:acme/x:write", 0},
		{"not_in allows non-blocked", "tag", map[string]any{"repo": "acme/site"}, "block-prod-repo", EffectAllow, "repo:acme/site:tag", 0},
		{"missing tool rule matches all", "anything", map[string]any{}, "global-audit-note", EffectAllow, "", 0},
		{"scope template failure denies", "get_repo", map[string]any{}, "read-free", EffectDeny, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Evaluate(tc.tool, tc.args)
			if d.RuleID != tc.wantRule || d.Effect != tc.wantEffect {
				t.Fatalf("got rule=%q effect=%q, want rule=%q effect=%q", d.RuleID, d.Effect, tc.wantRule, tc.wantEffect)
			}
			if d.Scope != tc.wantScope {
				t.Errorf("scope = %q, want %q", d.Scope, tc.wantScope)
			}
			if d.TTL != tc.wantTTL {
				t.Errorf("ttl = %v, want %v", d.TTL, tc.wantTTL)
			}
		})
	}
}

// TestImplicitDeny proves a call matching no rule is denied by default.
func TestImplicitDeny(t *testing.T) {
	e := mustLoad(t, "rules:\n  - id: only-reads\n    tool: get_repo\n    effect: allow\n")
	d := e.Evaluate("delete_repo", map[string]any{"repo": "x"})
	if d.Effect != EffectDeny || d.RuleID != "implicit-default-deny" {
		t.Fatalf("want implicit deny, got %+v", d)
	}
}

// TestConditionOperators exercises each operator's presence/absence behavior.
func TestConditionOperators(t *testing.T) {
	e := mustLoad(t, `
rules:
  - id: eq
    tool: t_eq
    when: { args.b: main }
    effect: allow
  - id: not
    tool: t_not
    when: { args.b: { not: main } }
    effect: allow
`)
	cases := []struct {
		tool string
		args map[string]any
		want Effect
	}{
		{"t_eq", map[string]any{"b": "main"}, EffectAllow},
		{"t_eq", map[string]any{"b": "dev"}, EffectDeny},
		{"t_eq", map[string]any{}, EffectDeny},             // absent → eq fails
		{"t_not", map[string]any{"b": "dev"}, EffectAllow}, // differs
		{"t_not", map[string]any{}, EffectAllow},           // absent → not matches
		{"t_not", map[string]any{"b": "main"}, EffectDeny}, // equal → not fails
	}
	for _, c := range cases {
		if got := e.Evaluate(c.tool, c.args).Effect; got != c.want {
			t.Errorf("%s %v: effect=%q want %q", c.tool, c.args, got, c.want)
		}
	}
}

// TestLoadErrors proves the loader is fail-loud on malformed policy.
func TestLoadErrors(t *testing.T) {
	bad := map[string]string{
		"unknown key":           "rules:\n  - id: x\n    tool: t\n    effect: allow\n    bogus: 1\n",
		"unknown operator":      "rules:\n  - id: x\n    tool: t\n    when: { args.b: { regex: '.*' } }\n    effect: allow\n",
		"typo beside valid op":  "rules:\n  - id: x\n    tool: t\n    when: { args.b: { not: y, reggex: '.*' } }\n    effect: allow\n",
		"no id":                 "rules:\n  - tool: t\n    effect: allow\n",
		"invalid effect":        "rules:\n  - id: x\n    tool: t\n    effect: maybe\n",
		"approval no approvers": "rules:\n  - id: x\n    tool: t\n    effect: require_approval\n",
		"empty":                 "rules: []\n",
	}
	for name, y := range bad {
		if _, err := Load(strings.NewReader(y)); err == nil {
			t.Errorf("%s: expected a load error, got nil", name)
		}
	}
}
