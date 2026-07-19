package api

import (
	"context"
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
func (s *Server) runLifecycleOnce(ctx context.Context, maxAge time.Duration, now time.Time) lifecycleReport {
	var rep lifecycleReport
	creds, err := s.store.ListCredentials(ctx, 0)
	if err != nil {
		s.log.Error("lifecycle: list credentials", "err", err)
		return rep
	}
	for i := range creds {
		cred := &creds[i]
		target, terr := s.store.GetTarget(ctx, cred.TargetID)
		if terr != nil {
			continue
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
					s.log.Error("lifecycle: rotate", "credential", cred.ID, "err", rerr)
				}
			}
		}
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
