// Package winrm runs commands on Windows targets over WinRM (WS-Management),
// with the credential injected just-in-time by the caller. The Runner interface
// is the seam tests inject a fake through; Client is the real implementation.
package winrm

import (
	"bytes"
	"context"
	"time"

	mw "github.com/masterzen/winrm"
)

// Result is the outcome of a remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Runner executes a command on a Windows host over WinRM.
type Runner interface {
	Run(ctx context.Context, host string, port int, user, password, command string) (Result, error)
}

// Client is the real WinRM runner (masterzen/winrm). Use HTTPS in production;
// Insecure skips TLS verification (dev only).
type Client struct {
	HTTPS    bool
	Insecure bool
	Timeout  time.Duration
}

func (c Client) Run(ctx context.Context, host string, port int, user, password, command string) (Result, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	endpoint := mw.NewEndpoint(host, port, c.HTTPS, c.Insecure, nil, nil, nil, timeout)
	client, err := mw.NewClient(endpoint, user, password)
	if err != nil {
		return Result{}, err
	}
	var stdout, stderr bytes.Buffer
	// A non-zero exit code is returned without an error; err is only for
	// transport/auth failures.
	code, err := client.RunWithContext(ctx, command, &stdout, &stderr)
	if err != nil {
		return Result{}, err
	}
	return Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: code}, nil
}
