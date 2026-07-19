package api

import "testing"

// TestRDPExtraSecureDefault verifies the default (unconfigured) RDP parameters
// neither disable certificate verification nor force an insecure security mode.
func TestRDPExtraSecureDefault(t *testing.T) {
	e := rdpExtra("", false)
	if v, ok := e["ignore-cert"]; ok && v == "true" {
		t.Fatalf("default must verify the RDP server cert, got ignore-cert=%q", v)
	}
	if _, ok := e["security"]; ok {
		t.Fatal("default must let guacd negotiate the security mode (no forced 'any')")
	}
}

// TestRDPExtraConfigured verifies an explicit security mode and cert-ignore opt-out
// are passed through to guacd.
func TestRDPExtraConfigured(t *testing.T) {
	e := rdpExtra("nla", true)
	if e["security"] != "nla" {
		t.Fatalf("security = %q, want nla", e["security"])
	}
	if e["ignore-cert"] != "true" {
		t.Fatalf("ignore-cert = %q, want true", e["ignore-cert"])
	}
}
