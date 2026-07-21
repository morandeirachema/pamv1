// Package ticket validates an ITSM change/incident ticket reference before
// privileged access is granted (Phase 20) — the "no access without an approved
// change ticket" control. Validation is two optional, composable checks: a
// regular-expression format (e.g. a ServiceNow/Jira number) and a webhook that
// the ITSM system answers 2xx for a valid ticket. A nil Validator accepts any
// ticket (validation disabled), so callers can hold one unconditionally.
package ticket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// Validator checks a ticket reference against a format pattern and/or a webhook.
type Validator struct {
	pattern *regexp.Regexp
	webhook string
	http    *http.Client
}

// New builds a Validator from an optional regex pattern and an optional webhook
// URL. When neither is set it returns (nil, nil) — validation is disabled.
func New(pattern, webhookURL string) (*Validator, error) {
	if pattern == "" && webhookURL == "" {
		return nil, nil
	}
	v := &Validator{webhook: webhookURL, http: &http.Client{Timeout: 8 * time.Second}}
	if pattern != "" {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("PAM_TICKET_PATTERN %q: %w", pattern, err)
		}
		v.pattern = re
	}
	return v, nil
}

// Enabled reports whether any validation is configured.
func (v *Validator) Enabled() bool { return v != nil }

// Validate returns nil if ticket is acceptable, else an error describing why. A
// nil Validator accepts any ticket. The webhook receives {"ticket": "<id>"} and
// a 2xx response means valid.
func (v *Validator) Validate(ctx context.Context, ticket string) error {
	if v == nil {
		return nil
	}
	if v.pattern != nil && !v.pattern.MatchString(ticket) {
		return fmt.Errorf("ticket %q does not match the required format", ticket)
	}
	if v.webhook == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"ticket": ticket})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("ticket validation request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ticket %q was rejected by the ITSM system (status %d)", ticket, resp.StatusCode)
	}
	return nil
}
