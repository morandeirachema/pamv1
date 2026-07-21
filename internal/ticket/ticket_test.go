package ticket

import (
	"context"
	"testing"
)

// TestValidatorPatternAndDisabled covers the no-webhook paths: disabled (nil),
// fail-loud on a bad pattern, nil accepts anything, and a pattern rejects.
func TestValidatorPatternAndDisabled(t *testing.T) {
	// Neither pattern nor webhook → disabled (nil, nil).
	v, err := New("", "")
	if err != nil || v != nil {
		t.Fatalf("disabled: got %v, %v; want nil, nil", v, err)
	}
	// A nil validator accepts any ticket.
	if err := v.Validate(context.Background(), "whatever"); err != nil {
		t.Fatalf("nil validator must accept: %v", err)
	}
	if v.Enabled() {
		t.Fatal("nil validator must report Enabled()=false")
	}

	// A malformed pattern is fail-loud.
	if _, err := New("(", ""); err == nil {
		t.Fatal("bad pattern must error")
	}

	// A pattern gates the format (no webhook configured).
	pv, err := New(`^CHG[0-9]{3,}$`, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := pv.Validate(context.Background(), "CHG1234"); err != nil {
		t.Fatalf("valid ticket rejected: %v", err)
	}
	if err := pv.Validate(context.Background(), "nope"); err == nil {
		t.Fatal("format-mismatched ticket must be rejected")
	}
}
