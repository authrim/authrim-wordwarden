package httpapi

import (
	"sync"
	"time"
)

type StormProtectionPolicy struct {
	WindowMS              int
	BlockMS               int
	MalformedRequestLimit int
	ReplayLimit           int
	DirectoryErrorLimit   int
}

type stormKind string

const (
	stormKindMalformed      stormKind = "malformed_request"
	stormKindReplay         stormKind = "replay"
	stormKindDirectoryError stormKind = "directory_error"
)

type connectorStorms struct {
	mu     sync.Mutex
	policy StormProtectionPolicy
	now    func() time.Time
	states map[stormKind]stormState
}

type stormState struct {
	windowStart  time.Time
	count        int
	blockedUntil time.Time
}

func newConnectorStorms(policy StormProtectionPolicy) *connectorStorms {
	return &connectorStorms{
		policy: defaultStormProtectionPolicy(policy),
		now:    time.Now,
		states: map[stormKind]stormState{},
	}
}

func defaultStormProtectionPolicy(policy StormProtectionPolicy) StormProtectionPolicy {
	if policy.WindowMS <= 0 {
		policy.WindowMS = 10000
	}
	if policy.BlockMS <= 0 {
		policy.BlockMS = 30000
	}
	if policy.MalformedRequestLimit <= 0 {
		policy.MalformedRequestLimit = 20
	}
	if policy.ReplayLimit <= 0 {
		policy.ReplayLimit = 10
	}
	if policy.DirectoryErrorLimit <= 0 {
		policy.DirectoryErrorLimit = 5
	}
	return policy
}

func (s *connectorStorms) blocked(kind stormKind) bool {
	now := s.now()

	s.mu.Lock()
	defer s.mu.Unlock()

	state := s.states[kind]
	if state.blockedUntil.IsZero() || !now.Before(state.blockedUntil) {
		return false
	}
	return true
}

func (s *connectorStorms) record(kind stormKind) {
	now := s.now()
	window := time.Duration(s.policy.WindowMS) * time.Millisecond
	block := time.Duration(s.policy.BlockMS) * time.Millisecond

	s.mu.Lock()
	defer s.mu.Unlock()

	state := s.states[kind]
	if state.windowStart.IsZero() || now.Sub(state.windowStart) > window {
		state.windowStart = now
		state.count = 0
	}

	state.count++
	if state.count >= s.limit(kind) {
		state.blockedUntil = now.Add(block)
	}
	s.states[kind] = state
}

func (s *connectorStorms) reset(kind stormKind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, kind)
}

func (s *connectorStorms) limit(kind stormKind) int {
	switch kind {
	case stormKindMalformed:
		return s.policy.MalformedRequestLimit
	case stormKindReplay:
		return s.policy.ReplayLimit
	case stormKindDirectoryError:
		return s.policy.DirectoryErrorLimit
	default:
		return 1
	}
}
