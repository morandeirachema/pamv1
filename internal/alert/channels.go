package alert

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/logging"
)

// alertTimeout bounds a single alert delivery (connect + I/O) so a stalled or
// blackholed syslog/SMTP endpoint cannot park the fire-and-forget goroutine
// indefinitely — matching the Webhook notifier's 10s budget.
const alertTimeout = 10 * time.Second

// oneLine replaces CR and LF with spaces so an untrusted field (an actor name
// from a directory claim) cannot inject extra lines into a syslog record or SMTP
// header.
func oneLine(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// Multi fans an alert out to several notifiers (e.g. webhook + syslog + email).
type Multi []Notifier

// Notify delivers e to every underlying notifier.
func (m Multi) Notify(ctx context.Context, e Event) {
	for _, n := range m {
		n.Notify(ctx, e)
	}
}

// stamp formats an event time as RFC3339, or "-" when unset (the caller stamps
// Time; alert code avoids calling time.Now itself).
func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// Syslog sends alerts as RFC 5424 messages to a syslog server over UDP or TCP,
// best-effort and non-blocking.
type Syslog struct {
	network string
	addr    string
	tag     string
	dial    func(network, addr string) (net.Conn, error)
}

// NewSyslog returns a Syslog notifier for the given transport ("udp"/"tcp") and
// address (host:port); tag defaults to "pamv1".
func NewSyslog(network, addr, tag string) *Syslog {
	if tag == "" {
		tag = "pamv1"
	}
	return &Syslog{network: network, addr: addr, tag: tag, dial: (&net.Dialer{Timeout: alertTimeout}).Dial}
}

// Notify formats the event as a syslog line (authpriv.alert priority) and sends
// it from a background goroutine; delivery errors are logged, not returned.
func (s *Syslog) Notify(_ context.Context, e Event) {
	// PRI = facility(authpriv=10)*8 + severity(alert=1) = 81. Strip CR/LF from
	// actor/type/remote (which can come from LDAP/OIDC claims) so a crafted name
	// cannot forge extra syslog records.
	msg := fmt.Sprintf("<81>1 %s - %s - %s - actor=%s detail=%q remote=%s",
		stamp(e.Time), s.tag, oneLine(e.Type), oneLine(e.Actor), e.Detail, oneLine(e.Remote))
	go func() {
		conn, err := s.dial(s.network, s.addr)
		if err != nil {
			logging.Component("alert").Warn("syslog alert failed", "type", e.Type, "err", err)
			return
		}
		defer conn.Close()
		// Bound the write so a connected-but-stalled TCP syslog sink cannot park
		// this goroutine forever (the dialer already bounds the connect).
		_ = conn.SetWriteDeadline(time.Now().Add(alertTimeout))
		_, _ = conn.Write([]byte(msg))
	}()
}

// Email sends alerts via SMTP, best-effort and non-blocking.
type Email struct {
	addr string // SMTP host:port
	from string
	to   []string
	auth smtp.Auth
	send func(addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

// NewEmail returns an Email notifier. When username is non-empty, PLAIN auth is
// used (host derived from addr); otherwise the relay is used unauthenticated.
func NewEmail(addr, from string, to []string, username, password string) *Email {
	var a smtp.Auth
	if username != "" {
		host := addr
		if h, _, err := net.SplitHostPort(addr); err == nil {
			host = h
		}
		a = smtp.PlainAuth("", username, password, host)
	}
	return &Email{addr: addr, from: from, to: to, auth: a, send: sendMailBounded}
}

// sendMailBounded is smtp.SendMail with a connect timeout and an I/O deadline, so
// a slow or blackholed relay cannot park the delivery goroutine indefinitely.
func sendMailBounded(addr string, a smtp.Auth, from string, to []string, msg []byte) error {
	conn, err := net.DialTimeout("tcp", addr, alertTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(alertTimeout)); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}
	if a != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(a); err != nil {
				return err
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write(msg); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// Notify formats a plain-text email and sends it from a background goroutine;
// delivery errors are logged, not returned.
func (m *Email) Notify(_ context.Context, e Event) {
	// Strip CR/LF so an actor/type from a directory claim cannot inject SMTP
	// headers via the Subject line.
	subject := fmt.Sprintf("[pamv1] %s by %s", oneLine(e.Type), oneLine(e.Actor))
	body := fmt.Sprintf("Type: %s\r\nActor: %s\r\nDetail: %s\r\nRemote: %s\r\nTime: %s\r\n",
		e.Type, e.Actor, e.Detail, e.Remote, stamp(e.Time))
	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s",
		m.from, strings.Join(m.to, ", "), subject, body))
	go func() {
		if err := m.send(m.addr, m.auth, m.from, m.to, msg); err != nil {
			logging.Component("alert").Warn("email alert failed", "type", e.Type, "err", err)
		}
	}()
}
