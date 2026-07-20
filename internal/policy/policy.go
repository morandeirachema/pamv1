// Package policy is the agent-access-broker decision engine. It matches a tool
// call and its arguments against an ordered rule set (sudoers-style) and returns
// allow / deny / require_approval. First matching rule wins; no match is an
// implicit deny (fail-closed). Conditions match the argument value only —
// there is deliberately no regex, numeric comparison, OR, or nesting.
package policy

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Effect is a rule outcome.
type Effect string

const (
	EffectAllow           Effect = "allow"
	EffectDeny            Effect = "deny"
	EffectRequireApproval Effect = "require_approval"
)

// Condition is a single argument matcher. Exactly one field is set (enforced at
// load time via UnmarshalYAML). Every condition on a rule must hold (AND).
type Condition struct {
	Eq    *string  // args.field: value        (equality; matches only when present)
	Not   *string  // args.field: { not: X }   (differs or absent)
	In    []string // args.field: { in: [...] }(present and in the allow-list)
	NotIn []string // args.field: { not_in: [...] } (absent or not in the block-list)
}

// UnmarshalYAML accepts either a scalar (equality) or a one-key mapping with
// not/in/not_in, and rejects anything else (e.g. an unknown operator) fail-loud.
func (c *Condition) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		s := value.Value
		c.Eq = &s
		return nil
	case yaml.MappingNode:
		// Reject unknown operator keys fail-loud: a typo (e.g. "reggex") paired with
		// a valid operator would otherwise load silently and enforce only the
		// accidental clause. value.Decode ignores unknown keys, so check them here.
		for i := 0; i+1 < len(value.Content); i += 2 {
			switch value.Content[i].Value {
			case "not", "in", "not_in":
			default:
				return fmt.Errorf("policy: unknown condition operator %q (want not|in|not_in)", value.Content[i].Value)
			}
		}
		var m struct {
			Not   *string  `yaml:"not"`
			In    []string `yaml:"in"`
			NotIn []string `yaml:"not_in"`
		}
		if err := value.Decode(&m); err != nil {
			return err
		}
		set := 0
		if m.Not != nil {
			c.Not = m.Not
			set++
		}
		if m.In != nil {
			c.In = m.In
			set++
		}
		if m.NotIn != nil {
			c.NotIn = m.NotIn
			set++
		}
		if set != 1 {
			return fmt.Errorf("policy: a condition must have exactly one of not/in/not_in")
		}
		return nil
	default:
		return fmt.Errorf("policy: condition must be a value or a {not|in|not_in} map")
	}
}

// match reports whether the condition holds for the argument value (val, present).
func (c Condition) match(val string, present bool) bool {
	switch {
	case c.Eq != nil:
		return present && val == *c.Eq
	case c.Not != nil:
		return !present || val != *c.Not
	case c.In != nil:
		return present && contains(c.In, val)
	case c.NotIn != nil:
		return !present || !contains(c.NotIn, val)
	}
	return false
}

// Rule is one policy entry. A missing Tool matches every tool (global rule).
type Rule struct {
	ID         string               `yaml:"id"`
	Tool       string               `yaml:"tool"`
	When       map[string]Condition `yaml:"when"`
	Effect     Effect               `yaml:"effect"`
	Approvers  []string             `yaml:"approvers"`
	Scope      string               `yaml:"scope"`
	TTLSeconds int                  `yaml:"ttl_seconds"`
	Reason     string               `yaml:"reason"`
}

// Decision is the engine's verdict for a tool call.
type Decision struct {
	RuleID    string
	Effect    Effect
	Scope     string
	TTL       time.Duration
	Approvers []string
	Reason    string
}

// Engine holds an ordered, validated rule set.
type Engine struct {
	rules []Rule
}

type policyFile struct {
	Rules []Rule `yaml:"rules"`
}

// Load parses a YAML policy from r, rejecting unknown keys (fail-loud) and
// validating that every rule has an id and a known effect.
func Load(r io.Reader) (*Engine, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var f policyFile
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("policy: no rules defined")
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("policy: rule at index %d has no id", i)
		}
		switch r.Effect {
		case EffectAllow, EffectDeny, EffectRequireApproval:
		default:
			return nil, fmt.Errorf("policy: rule %q has invalid effect %q", r.ID, r.Effect)
		}
		if r.Effect == EffectRequireApproval && len(r.Approvers) == 0 {
			return nil, fmt.Errorf("policy: rule %q requires approval but lists no approvers", r.ID)
		}
	}
	return &Engine{rules: f.Rules}, nil
}

// LoadFile reads and parses a policy file from path.
func LoadFile(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Load(bytes.NewReader(data))
}

// Rules returns the number of loaded rules (for startup logging).
func (e *Engine) Rules() int { return len(e.rules) }

// Evaluate returns the decision for a tool call. It scans rules top-to-bottom,
// returning the first whose tool and conditions match; a scope-template failure
// on a matched rule is a deny, and no match at all is the implicit default deny.
func (e *Engine) Evaluate(tool string, args map[string]any) Decision {
	for _, r := range e.rules {
		if r.Tool != "" && r.Tool != tool {
			continue
		}
		if !matchAll(r.When, args) {
			continue
		}
		scope, ok := renderScope(r.Scope, args)
		if !ok {
			return Decision{RuleID: r.ID, Effect: EffectDeny, Reason: "scope template failed: missing argument"}
		}
		return Decision{
			RuleID:    r.ID,
			Effect:    r.Effect,
			Scope:     scope,
			TTL:       time.Duration(r.TTLSeconds) * time.Second,
			Approvers: r.Approvers,
			Reason:    r.Reason,
		}
	}
	return Decision{RuleID: "implicit-default-deny", Effect: EffectDeny, Reason: "no rule matched"}
}

// matchAll reports whether every condition in when holds for args (AND logic).
func matchAll(when map[string]Condition, args map[string]any) bool {
	for field, cond := range when {
		key := strings.TrimPrefix(field, "args.")
		val, present := args[key]
		if !cond.match(stringify(val), present) {
			return false
		}
	}
	return true
}

var scopeVar = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// renderScope substitutes {arg} placeholders in tmpl from args. It returns
// ok=false if any referenced argument is absent (the caller treats that as deny).
func renderScope(tmpl string, args map[string]any) (string, bool) {
	if tmpl == "" {
		return "", true
	}
	ok := true
	out := scopeVar.ReplaceAllStringFunc(tmpl, func(m string) string {
		name := m[1 : len(m)-1]
		v, present := args[name]
		if !present {
			ok = false
			return m
		}
		return stringify(v)
	})
	return out, ok
}

// stringify renders an argument value (from JSON: string/number/bool) as the
// string the policy compares against.
func stringify(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// contains reports whether xs includes s.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
