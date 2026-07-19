package alert

import (
	"context"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

// TestSyslogNotify sends an alert to an in-process UDP listener and checks the
// RFC 5424 line carries the event.
func TestSyslogNotify(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	s := NewSyslog("udp", pc.LocalAddr().String(), "pamv1")
	s.Notify(context.Background(), Event{Type: "breakglass.access", Actor: "alice", Detail: "x", Time: time.Now()})

	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no syslog datagram: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "<81>1 ") {
		t.Fatalf("bad syslog prefix: %q", got)
	}
	if !strings.Contains(got, "breakglass.access") || !strings.Contains(got, "actor=alice") {
		t.Fatalf("syslog line missing event: %q", got)
	}
}

// TestEmailNotify checks the SMTP message is formed with the subject, body and
// recipients (send is stubbed — no real SMTP server).
func TestEmailNotify(t *testing.T) {
	gotMsg := make(chan []byte, 1)
	var gotTo []string
	e := &Email{
		addr: "smtp.internal:25", from: "pam@example.com", to: []string{"a@x", "b@x"},
		send: func(_ string, _ smtp.Auth, _ string, to []string, msg []byte) error {
			gotTo = to
			gotMsg <- msg
			return nil
		},
	}
	e.Notify(context.Background(), Event{Type: "breakglass.unseal", Actor: "bob"})

	select {
	case msg := <-gotMsg:
		s := string(msg)
		if !strings.Contains(s, "Subject: [pamv1] breakglass.unseal by bob") || !strings.Contains(s, "Type: breakglass.unseal") {
			t.Fatalf("email body missing fields: %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("email was not sent")
	}
	if len(gotTo) != 2 {
		t.Fatalf("recipients = %v", gotTo)
	}
}

// captureNotifier records events for the Multi test.
type captureNotifier struct{ ch chan Event }

// Notify records e.
func (c captureNotifier) Notify(_ context.Context, e Event) { c.ch <- e }

// TestMultiFansOut checks Multi delivers to every notifier.
func TestMultiFansOut(t *testing.T) {
	a := captureNotifier{make(chan Event, 1)}
	b := captureNotifier{make(chan Event, 1)}
	Multi{a, b}.Notify(context.Background(), Event{Type: "x"})
	for _, c := range []captureNotifier{a, b} {
		select {
		case <-c.ch:
		case <-time.After(time.Second):
			t.Fatal("Multi did not deliver to a notifier")
		}
	}
}
