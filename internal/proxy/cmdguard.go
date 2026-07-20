package proxy

// cmdguard.go implements command control: a policy-driven denylist that blocks a
// dangerous command before it reaches the target. It applies to the request
// paths where a discrete command is visible — SSH `exec` (non-interactive
// `ssh target "cmd"`), each WinRM command-loop line, and each PostgreSQL
// statement. Interactive SSH shells stream a raw PTY and are not parsed here;
// use read-only observer sessions or restrict shell access for those.

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// CommandGuard blocks commands matching any of its deny patterns. A nil guard
// blocks nothing, so callers can hold one unconditionally.
type CommandGuard struct {
	patterns []*regexp.Regexp
}

// NewCommandGuard compiles the given regular expressions into a guard. Blank
// lines and lines beginning with '#' are ignored, so a deny file can carry
// comments. A malformed pattern is a fail-loud error.
func NewCommandGuard(patterns []string) (*CommandGuard, error) {
	var ps []*regexp.Regexp
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("command-deny pattern %q: %w", p, err)
		}
		ps = append(ps, re)
	}
	if len(ps) == 0 {
		return nil, nil
	}
	return &CommandGuard{patterns: ps}, nil
}

// ParseCommandDeny splits a deny file's contents into one pattern per line.
func ParseCommandDeny(contents string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(contents))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// Blocked reports the first deny pattern that matches cmd, if any. A nil guard
// never blocks.
func (g *CommandGuard) Blocked(cmd string) (pattern string, blocked bool) {
	if g == nil {
		return "", false
	}
	for _, re := range g.patterns {
		if re.MatchString(cmd) {
			return re.String(), true
		}
	}
	return "", false
}

// Size reports how many patterns the guard holds (0 for a nil guard).
func (g *CommandGuard) Size() int {
	if g == nil {
		return 0
	}
	return len(g.patterns)
}
