package api

import (
	"context"
	"fmt"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/broker"
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
		WithArgCap(opts.BrokerMaxArgBytes)
	s.brokerLimiter = newRateLimiter(opts.BrokerRatePerMin)
	s.agentVerifier = agentid.NewStaticVerifier(s.store)
	s.log.Info("agent access broker enabled", "tools", len(reg.List()), "policy_rules", opts.BrokerPolicy.Rules())
	return nil
}
