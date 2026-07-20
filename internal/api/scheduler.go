package api

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
)

// RotationPolicy configures the background credential-lifecycle worker.
type RotationPolicy struct {
	// Interval is how often the worker runs (0 disables it).
	Interval time.Duration
	// MaxAge rotates password credentials whose secret is older than this
	// (0 = reconcile/report only, never auto-rotate).
	MaxAge time.Duration
}

// lifecycleReport summarizes one worker pass.
type lifecycleReport struct {
	Checked   int
	OutOfSync int
	Rotated   int
}

// systemContext is the actor context the scheduler audits under.
func systemContext(ctx context.Context) context.Context {
	return withPrincipal(ctx, &auth.Principal{Name: "system-scheduler", Role: auth.RoleAdmin})
}

// RotateCredentialByID rotates a single credential by ID and audits the result.
// It is the entry point the SSH proxy calls to force post-session rotation
// (actor system-scheduler); a missing credential/target is a no-op with a log.
func (s *Server) RotateCredentialByID(ctx context.Context, credentialID int64) {
	ctx = systemContext(ctx)
	cred, err := s.store.GetCredential(ctx, credentialID)
	if err != nil {
		s.log.Warn("post-session rotation: credential not found", "credential", credentialID, "err", err)
		return
	}
	target, err := s.store.GetTarget(ctx, cred.TargetID)
	if err != nil {
		s.log.Warn("post-session rotation: target not found", "credential", credentialID, "err", err)
		return
	}
	if _, err := s.rotateCredential(ctx, cred, target); err != nil {
		s.audit(ctx, "credential.rotate_failed", fmt.Sprintf("credential:%d reason:post-session error:%v", cred.ID, err))
		s.log.Error("post-session rotation failed", "credential", cred.ID, "err", err)
		return
	}
	s.audit(ctx, "credential.rotate", fmt.Sprintf("credential:%d target:%s reason:post-session", cred.ID, target.Name))
}

// invalidateCheckout closes an expired-but-unreturned lease and rotates the
// credential behind it, so the secret its holder saw stops working. Closing the
// lease first (idempotent) acts as a claim: if a concurrent sweep or check-in
// already returned it, CheckinCheckout errors and we skip, so the credential is
// never rotated twice for the same expiry. Returns (true, nil) when it rotated,
// (false, nil) when the claim was lost or the credential/target vanished, and
// (false, err) when the rotation itself failed (already audited).
func (s *Server) invalidateCheckout(ctx context.Context, co store.Checkout, now time.Time) (bool, error) {
	if err := s.store.CheckinCheckout(ctx, co.ID, now); err != nil {
		return false, nil // a concurrent sweep or check-in already closed this lease
	}
	cred, err := s.store.GetCredential(ctx, co.CredentialID)
	if err != nil {
		return false, nil
	}
	target, err := s.store.GetTarget(ctx, cred.TargetID)
	if err != nil {
		return false, nil
	}
	if _, rerr := s.rotateCredential(ctx, cred, target); rerr != nil {
		s.audit(ctx, "credential.checkin_rotate_failed",
			fmt.Sprintf("credential:%d reason:checkout-expired error:%v", cred.ID, rerr))
		return false, rerr
	}
	s.audit(ctx, "credential.rotate",
		fmt.Sprintf("credential:%d target:%s reason:checkout-expired", cred.ID, target.Name))
	return true, nil
}

// sweepExpiredCheckouts rotates the credential behind every expired-but-unreturned
// checkout and marks the lease returned, so a secret revealed at checkout stops
// working even when the holder never checks it back in. Returns the count rotated.
func (s *Server) sweepExpiredCheckouts(ctx context.Context, now time.Time) int {
	cos, err := s.store.ListCheckouts(ctx, false, now)
	if err != nil {
		s.log.Error("lifecycle: list checkouts", "err", err)
		return 0
	}
	rotated := 0
	for i := range cos {
		co := cos[i]
		if co.ReturnedAt != nil || !co.ExpiresAt.Before(now) {
			continue // already returned, or still active
		}
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("lifecycle: panic sweeping checkout", "checkout", co.ID, "panic", p)
				}
			}()
			if ok, _ := s.invalidateCheckout(ctx, co, now); ok {
				rotated++
			}
		}()
	}
	return rotated
}

// invalidateExpiredCheckoutFor rotates and closes an expired-but-unreturned lease
// on credentialID (if any) before the credential is handed to a new holder, so a
// re-checkout that races ahead of the periodic sweep can never reuse an expired
// holder's still-valid secret. Returns whether it rotated; an error means an
// expired lease existed but could not be invalidated (the caller must not proceed).
func (s *Server) invalidateExpiredCheckoutFor(ctx context.Context, credentialID int64, now time.Time) (bool, error) {
	cos, err := s.store.ListCheckouts(ctx, false, now)
	if err != nil {
		return false, err
	}
	for i := range cos {
		co := cos[i]
		if co.CredentialID != credentialID || co.ReturnedAt != nil || !co.ExpiresAt.Before(now) {
			continue
		}
		return s.invalidateCheckout(ctx, co, now)
	}
	return false, nil
}

// RunLifecycleWorker runs the credential-lifecycle worker until ctx is cancelled:
// on each tick it reconciles every credential (detecting drift) and rotates any
// password credential older than pol.MaxAge. It is safe to call in a goroutine.
func (s *Server) RunLifecycleWorker(ctx context.Context, pol RotationPolicy) {
	if pol.Interval <= 0 {
		return
	}
	s.log.Info("credential-lifecycle worker started", "interval", pol.Interval.String(), "max_age", pol.MaxAge.String())
	ticker := time.NewTicker(pol.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rep := s.runLifecycleOnce(systemContext(ctx), pol.MaxAge, time.Now())
			s.log.Info("credential-lifecycle pass",
				"checked", rep.Checked, "out_of_sync", rep.OutOfSync, "rotated", rep.Rotated)
		}
	}
}

// runLifecycleOnce performs a single reconcile+age-rotation pass. now is passed
// explicitly so the aging decision is testable.
// RunBrokerTokenGC periodically deletes spent or expired agent-broker resume
// tokens so the broker_tokens table stays bounded. It runs only when the broker
// is enabled and stops when ctx is cancelled.
func (s *Server) RunBrokerTokenGC(ctx context.Context) {
	if s.broker == nil {
		return
	}
	const interval = 10 * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := s.store.DeleteExpiredBrokerTokens(systemContext(ctx)); err != nil {
				s.log.Warn("broker token GC failed", "err", err)
			} else if n > 0 {
				s.log.Debug("broker token GC swept expired/used tokens", "deleted", n)
			}
		}
	}
}

func (s *Server) runLifecycleOnce(ctx context.Context, maxAge time.Duration, now time.Time) lifecycleReport {
	var rep lifecycleReport
	// Invalidate any secret still outstanding on an expired checkout that was
	// never returned, so "the password the holder saw stops working" holds even
	// without an explicit check-in.
	rep.Rotated += s.sweepExpiredCheckouts(ctx, now)
	creds, err := s.store.ListCredentials(ctx, 0)
	if err != nil {
		s.log.Error("lifecycle: list credentials", "err", err)
		return rep
	}
	for i := range creds {
		cred := &creds[i]
		// Isolate each credential: a panic in a third-party-backed connector must
		// not crash the worker goroutine (and with it the whole process).
		func() {
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("lifecycle: panic handling credential", "credential", cred.ID, "panic", p)
				}
			}()
			target, terr := s.store.GetTarget(ctx, cred.TargetID)
			if terr != nil {
				s.log.Warn("lifecycle: target lookup failed", "credential", cred.ID, "err", terr)
				return
			}
			res := s.reconcileOne(ctx, cred, target, false)
			rep.Checked++
			if res.Status == "out_of_sync" {
				rep.OutOfSync++
			}
			if maxAge > 0 && cred.SecretType == "password" && credentialAge(cred, now) > maxAge {
				if _, ok := s.rotators[target.Protocol]; ok {
					if _, rerr := s.rotateCredential(ctx, cred, target); rerr == nil {
						rep.Rotated++
						s.audit(ctx, "credential.rotate",
							"credential:"+strconv.FormatInt(cred.ID, 10)+" target:"+target.Name+" reason:max-age")
					} else {
						s.audit(ctx, "credential.rotate_failed",
							fmt.Sprintf("credential:%d target:%s reason:max-age error:%v", cred.ID, target.Name, rerr))
						s.log.Error("lifecycle: rotate", "credential", cred.ID, "err", rerr)
					}
				}
			}
		}()
	}
	return rep
}

// credentialAge is the time since the secret was last set (rotated, else created).
func credentialAge(cred *store.Credential, now time.Time) time.Duration {
	last := cred.CreatedAt
	if cred.RotatedAt != nil {
		last = *cred.RotatedAt
	}
	return now.Sub(last)
}
