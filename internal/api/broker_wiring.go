package api

import (
	"context"
	"fmt"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/ratelimit"
)

// setupBroker constructs the AI-agent access broker when a policy engine is
// supplied (Phase 13). It builds the tamper-evident audit chain, the tool
// registry, and the agent-key verifier. A nil policy leaves the broker disabled.
func (s *Server) setupBroker(opts Options) error {
	if opts.BrokerPolicy == nil {
		return nil
	}
	chain, err := auditchain.New(context.Background(), opts.BrokerAuditKey, opts.BrokerAuditSignKey, s.store)
	if err != nil {
		return fmt.Errorf("api: broker audit chain: %w", err)
	}
	reg := broker.NewRegistry()
	s.registerBrokerTools(reg)
	s.auditChain = chain
	s.broker = broker.New(opts.BrokerPolicy, reg, chain).
		WithApproval(s.store, s.alerter, opts.BrokerTokenTTL).
		WithArgCap(opts.BrokerMaxArgBytes).
		WithRevalidator(s.revalidateAgent)
	s.brokerLimiter = ratelimit.New(opts.BrokerRatePerMin)
	// Static agent keys are always accepted; a SPIFFE SVID verifier, when
	// configured, is tried alongside them (Phase 13d).
	verifier := agentid.MultiVerifier{agentid.NewStaticVerifier(s.store)}
	if opts.BrokerSVIDVerifier != nil {
		verifier = append(verifier, opts.BrokerSVIDVerifier)
	}
	s.agentVerifier = verifier
	s.log.Info("agent access broker enabled", "tools", len(reg.List()), "policy_rules", opts.BrokerPolicy.Rules())
	return nil
}

// revalidateAgent reports whether a parked call's agent identity is still valid at
// approval time: an SVID must not have expired, and a static agent key must not
// have been revoked or disabled since the call was parked.
func (s *Server) revalidateAgent(ctx context.Context, id *agentid.Identity) bool {
	if !id.ExpiresAt.IsZero() && time.Now().After(id.ExpiresAt) {
		return false
	}
	if id.KeyID > 0 {
		k, err := s.store.GetAgentKey(ctx, id.KeyID)
		if err != nil || k.Disabled {
			return false
		}
	}
	return true
}
