package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
)

// rdpTunnel bridges a browser WebSocket to a guacd RDP session for a Windows
// target. The credential is decrypted just-in-time and injected into the guacd
// handshake — it reaches guacd (which drives RDP) but never the browser, which
// only receives the rendered display. Requires CapConnect.
//
// The token is read from the query string because browsers cannot set custom
// headers on a WebSocket handshake; prefer a short-lived session token.
func (s *Server) rdpTunnel(w http.ResponseWriter, r *http.Request) {
	if s.guacdAddr == "" {
		writeError(w, http.StatusNotFound, "RDP is not configured")
		return
	}
	principal, err := s.resolver.Resolve(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	if principal.EnrollOnly || !principal.Role.Can(auth.CapConnect) {
		writeError(w, http.StatusForbidden, "your role does not permit RDP access")
		return
	}
	id, ok := idParam(w, r)
	if !ok {
		return
	}
	target, err := s.store.GetTarget(r.Context(), id)
	if err != nil {
		storeError(w, err)
		return
	}
	if target.Protocol != "rdp" {
		writeError(w, http.StatusUnprocessableEntity, "target protocol is not rdp")
		return
	}
	if !s.protocolAllowed("rdp") {
		writeError(w, http.StatusForbidden, "rdp is not allowed by policy")
		return
	}
	grants, err := s.store.ListTargetGrants(r.Context(), target.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	if !auth.CanConnectTarget(principal, grants) {
		writeError(w, http.StatusForbidden, "not authorized for this target")
		return
	}
	if s.requireApprovalFor(target) && !principal.BreakGlass {
		approved, aerr := s.store.HasActiveApproval(r.Context(), principal.Name, target.ID, time.Now())
		if aerr != nil {
			storeError(w, aerr)
			return
		}
		if !approved {
			s.audit(withPrincipal(r.Context(), principal), "access.denied", "target:"+target.Name+" reason:approval-required")
			writeError(w, http.StatusForbidden, "connection requires an approved access request")
			return
		}
	}
	creds, err := s.store.ListCredentials(r.Context(), target.ID)
	if err != nil {
		storeError(w, err)
		return
	}
	if len(creds) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "target has no credential")
		return
	}
	cred := creds[0]
	secret, err := s.vault.Decrypt(r.Context(), cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		s.audit(withPrincipal(r.Context(), principal), "credential.decrypt_failed", fmt.Sprintf("credential:%d target:%s op:rdp", cred.ID, target.Name))
		writeError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	ctx := withPrincipal(r.Context(), principal)
	port := target.Port
	if port == 0 {
		port = 3389
	}
	var recName string
	if s.guacdRecordingPath != "" {
		recName = fmt.Sprintf("%d_%s_%s", time.Now().UnixNano(), sanitizeName(target.Name), sanitizeName(principal.Name))
	}
	gconn, err := guacd.Connect(ctx, s.guacdAddr, guacd.Params{
		Protocol: "rdp", Hostname: target.Host, Port: strconv.Itoa(port),
		Username: cred.Username, Password: secret,
		Width:         atoiOr(r.URL.Query().Get("width"), 1024),
		Height:        atoiOr(r.URL.Query().Get("height"), 768),
		RecordingPath: s.guacdRecordingPath,
		RecordingName: recName,
		Extra:         rdpExtra(s.guacdRDPSecurity, s.guacdIgnoreCert),
	})
	if err != nil {
		s.log.Error("rdp connect failed", "target", target.Name, "err", err)
		s.audit(ctx, "rdp.error", "target:"+target.Name+" error:"+err.Error())
		writeError(w, http.StatusBadGateway, "rdp connection failed")
		return
	}
	defer gconn.Close()

	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		return // Accept already wrote the response
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	s.audit(ctx, "rdp.connect", "target:"+target.Name+" cred_user:"+cred.Username+" recording:"+recName)
	defer s.audit(ctx, "rdp.end", "target:"+target.Name)
	s.log.Info("rdp session", "actor", principal.Name, "target", target.Name)

	if s.sessions != nil {
		sid := s.sessions.Register(session.Info{
			Actor: principal.Name, Target: target.Name, Protocol: "rdp", Remote: r.RemoteAddr, Started: time.Now(),
		}, func() { gconn.Close() })
		defer s.sessions.Remove(sid)
	}

	bridgeGuacd(ctx, ws, gconn)
}

// bridgeGuacd pipes Guacamole protocol text between the browser WebSocket and
// the guacd connection until either side closes.
func bridgeGuacd(ctx context.Context, ws *websocket.Conn, gconn *guacd.Conn) {
	done := make(chan struct{}, 2)
	go func() { // guacd → browser
		buf := make([]byte, 8192)
		for {
			n, err := gconn.Read(buf)
			if n > 0 {
				if werr := ws.Write(ctx, websocket.MessageText, buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() { // browser → guacd
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				break
			}
			if _, werr := gconn.Write(data); werr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
}

// atoiOr parses s as a positive int, returning def when s is empty, non-numeric,
// or non-positive.
func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

// rdpExtra builds the guacd RDP security parameters. By default (security == ""
// and ignoreCert == false) it sets neither, so guacd negotiates the security mode
// and verifies the RDP server certificate. A security mode is passed through when
// set; ignore-cert is only sent (disabling cert verification) when explicitly
// enabled for dev/self-signed hosts.
func rdpExtra(security string, ignoreCert bool) map[string]string {
	extra := map[string]string{}
	if security != "" {
		extra["security"] = security
	}
	if ignoreCert {
		extra["ignore-cert"] = "true"
	}
	return extra
}
