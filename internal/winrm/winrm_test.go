package winrm

import (
	"testing"

	mw "github.com/masterzen/winrm"
)

// TestNewClientAuthSelection checks that both auth modes construct a client
// without error (the NTLM path must not mutate shared library defaults).
func TestNewClientAuthSelection(t *testing.T) {
	for _, ntlm := range []bool{false, true} {
		c := Client{HTTPS: true, NTLM: ntlm}
		endpoint := mw.NewEndpoint("host", 5986, true, false, nil, nil, nil, 0)
		if _, err := c.newClient(endpoint, "CONTOSO\\svc", "pw"); err != nil {
			t.Fatalf("newClient(ntlm=%v): %v", ntlm, err)
		}
	}
	// NTLM construction must not have mutated the library's shared defaults.
	if mw.DefaultParameters.TransportDecorator != nil {
		t.Fatal("NTLM path mutated masterzen/winrm DefaultParameters")
	}
}
