// Package guacd speaks the Apache Guacamole protocol to a guacd daemon so
// pamv1 can broker RDP (and VNC/SSH) sessions to Windows targets. The target's
// credential is injected just-in-time into the guacd handshake — it never
// reaches the operator's browser, which only sees the rendered display.
//
// Protocol reference: https://guacamole.apache.org/doc/gug/guacamole-protocol.html
package guacd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Instruction is a decoded Guacamole instruction: an opcode and its arguments.
type Instruction struct {
	Opcode string
	Args   []string
}

// Encode renders the instruction in the wire format: ELEMENT,ELEMENT,...;
// where each ELEMENT is LENGTH.VALUE (LENGTH is the Unicode code-point count).
func (i Instruction) Encode() string {
	var b strings.Builder
	writeElement(&b, i.Opcode)
	for _, a := range i.Args {
		b.WriteByte(',')
		writeElement(&b, a)
	}
	b.WriteByte(';')
	return b.String()
}

// writeElement writes s as a LENGTH.VALUE element, where LENGTH is its Unicode
// code-point count.
func writeElement(b *strings.Builder, s string) {
	fmt.Fprintf(b, "%d.%s", len([]rune(s)), s)
}

// readInstruction parses one instruction terminated by ';'.
func readInstruction(r *bufio.Reader) (Instruction, error) {
	var elems []string
	for {
		// Read the length prefix up to '.'.
		lenStr, err := r.ReadString('.')
		if err != nil {
			return Instruction{}, err
		}
		n, err := strconv.Atoi(strings.TrimRight(lenStr, "."))
		// Cap the element length: guacd instructions are KB-scale, so a corrupt or
		// hostile "999999999999." reply must not drive a multi-GB allocation.
		if err != nil || n < 0 || n > 1<<20 {
			return Instruction{}, fmt.Errorf("guacd: bad length %q", lenStr)
		}
		val := make([]rune, n)
		for i := 0; i < n; i++ {
			c, _, err := r.ReadRune()
			if err != nil {
				return Instruction{}, err
			}
			val[i] = c
		}
		elems = append(elems, string(val))
		// Separator: ',' → more elements, ';' → end.
		sep, _, err := r.ReadRune()
		if err != nil {
			return Instruction{}, err
		}
		if sep == ';' {
			break
		}
		if sep != ',' {
			return Instruction{}, fmt.Errorf("guacd: unexpected separator %q", sep)
		}
	}
	if len(elems) == 0 {
		return Instruction{}, fmt.Errorf("guacd: empty instruction")
	}
	return Instruction{Opcode: elems[0], Args: elems[1:]}, nil
}

// Params carries the connection settings; Credentials are injected JIT.
type Params struct {
	Protocol string // rdp | vnc | ...
	Hostname string
	Port     string
	Username string
	Password string
	Domain   string
	Width    int
	Height   int
	DPI      int
	// RecordingPath/RecordingName make guacd record the session server-side.
	RecordingPath string
	RecordingName string
	// Extra holds any additional guacd parameters (e.g. "security", "ignore-cert").
	Extra map[string]string
}

// Conn is a live guacd connection after a completed handshake. Read/Write carry
// the raw Guacamole protocol stream to bridge to the browser tunnel.
type Conn struct {
	net.Conn
	r  *bufio.Reader
	ID string
}

// Read reads from the buffered reader, so any bytes buffered during the
// handshake are delivered to the interactive stream rather than lost.
func (c *Conn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Connect dials guacd at addr and performs the handshake for params, injecting
// the credential just-in-time. It returns a Conn ready to be tunnelled.
func Connect(ctx context.Context, addr string, params Params) (*Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("guacd: dial: %w", err)
	}
	// Bound the handshake even when ctx has no deadline (the RDP tunnel passes a
	// request context that carries none): a guacd that accepts the dial but never
	// replies would otherwise block the handler goroutine forever.
	hsDeadline := time.Now().Add(30 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(hsDeadline) {
		hsDeadline = dl
	}
	nc.SetDeadline(hsDeadline)
	c := &Conn{Conn: nc, r: bufio.NewReader(nc)}
	id, err := c.handshake(params)
	if err != nil {
		nc.Close()
		return nil, err
	}
	c.ID = id
	nc.SetDeadline(time.Time{}) // clear the handshake deadline for the long-lived tunnel phase
	return c, nil
}

// send encodes and writes a single Guacamole instruction.
func (c *Conn) send(opcode string, args ...string) error {
	_, err := c.Conn.Write([]byte(Instruction{Opcode: opcode, Args: args}.Encode()))
	return err
}

// handshake performs the Guacamole select/args/size/connect/ready exchange,
// injecting the credential value guacd requests for each advertised arg, and
// returns the connection id from the ready reply.
func (c *Conn) handshake(p Params) (string, error) {
	// 1. select the protocol.
	if err := c.send("select", p.Protocol); err != nil {
		return "", err
	}
	// 2. guacd replies with the list of parameter names it expects.
	argsInst, err := readInstruction(c.r)
	if err != nil {
		return "", err
	}
	if argsInst.Opcode != "args" {
		return "", fmt.Errorf("guacd: expected args, got %q", argsInst.Opcode)
	}
	// 3. client capabilities.
	w, h, dpi := p.Width, p.Height, p.DPI
	if w == 0 {
		w = 1024
	}
	if h == 0 {
		h = 768
	}
	if dpi == 0 {
		dpi = 96
	}
	if err := c.send("size", strconv.Itoa(w), strconv.Itoa(h), strconv.Itoa(dpi)); err != nil {
		return "", err
	}
	if err := c.send("audio"); err != nil {
		return "", err
	}
	if err := c.send("video"); err != nil {
		return "", err
	}
	if err := c.send("image"); err != nil {
		return "", err
	}
	// 4. connect with a value for each requested arg (JIT credential injection).
	values := make([]string, len(argsInst.Args))
	for i, name := range argsInst.Args {
		values[i] = p.value(name)
	}
	if err := c.send("connect", values...); err != nil {
		return "", err
	}
	// 5. guacd confirms with ready + a connection id.
	ready, err := readInstruction(c.r)
	if err != nil {
		return "", err
	}
	if ready.Opcode != "ready" || len(ready.Args) == 0 {
		return "", fmt.Errorf("guacd: expected ready, got %q", ready.Opcode)
	}
	return ready.Args[0], nil
}

// value maps a guacd arg name to the connection value, injecting credentials.
func (p Params) value(name string) string {
	if strings.HasPrefix(name, "VERSION_") { // protocol version token → echo back
		return name
	}
	switch name {
	case "hostname":
		return p.Hostname
	case "port":
		return p.Port
	case "username":
		return p.Username
	case "password":
		return p.Password
	case "domain":
		return p.Domain
	case "recording-path":
		return p.RecordingPath
	case "recording-name":
		return p.RecordingName
	case "create-recording-path":
		if p.RecordingPath != "" {
			return "true"
		}
		return ""
	}
	if v, ok := p.Extra[name]; ok {
		return v
	}
	return ""
}
