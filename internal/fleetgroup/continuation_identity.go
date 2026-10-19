package fleetgroup

import (
	"context"
	"encoding/json"
	"math"
	"strings"
)

func continuationClone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func continuationIdentityRoot(e ContinuationEnvelope) ContinuationIdentityAnchor {
	return ContinuationIdentityAnchor{e.Authorization.ChainID, 0, Digest(struct{ Domain, Chain string }{"fleet-group-continuation-identities-v1", Digest(e)})}
}

// These are deterministic hash operations, not proof of publication/currentness.
// A repository must persist prefixes with the same atomic cursor/identity CAS.
func ContinuationIdentityBase(e ContinuationEnvelope) ContinuationIdentityAnchor {
	return continuationIdentityRoot(e)
}
func ContinuationIdentityExtend(a ContinuationIdentityAnchor, e ContinuationIdentity) (ContinuationIdentityAnchor, error) {
	return continuationIdentityAdd(a, e)
}
func continuationIdentityCode(k ContinuationIdentityKey) string { return k.Namespace + "\x00" + k.ID }
func continuationIdentityValid(e ContinuationIdentity) bool {
	if !hashPattern.MatchString(e.SHA256) || len(e.Key.ID) < 1 || len(e.Key.ID) > 512 || strings.ContainsAny(e.Key.ID, "\x00\r\n") {
		return false
	}
	switch e.Key.Namespace {
	case "COMMAND_ID", "OPERATION_ID", "COMMAND_KEY", "SIGNED_ID", "NONCE", "RECEIPT_ID", "RECEIPT_KEY":
		return true
	}
	return false
}
func continuationIdentityAdd(a ContinuationIdentityAnchor, e ContinuationIdentity) (ContinuationIdentityAnchor, error) {
	if !continuationIdentityValid(e) || !hashPattern.MatchString(a.SHA256) || !idPattern.MatchString(a.ChainID) || a.Count == math.MaxUint64 {
		return a, invalid("CONTINUATION_IDENTITY_INVALID")
	}
	return ContinuationIdentityAnchor{a.ChainID, a.Count + 1, Digest(struct {
		Previous string
		Entry    ContinuationIdentity
	}{a.SHA256, e})}, nil
}
func continuationReserved(ns, id string) ContinuationIdentity {
	return ContinuationIdentity{ContinuationIdentityKey{ns, id}, Digest(struct{ Namespace, ID string }{ns, id})}
}

type continuationIdentities struct {
	ctx           context.Context
	authority     ContinuationAuthority
	chain         string
	base, current ContinuationIdentityAnchor
	local         map[string]ContinuationIdentity
	added         []ContinuationIdentity
}

func newContinuationIdentities(ctx context.Context, a ContinuationAuthority, base ContinuationIdentityAnchor) *continuationIdentities {
	return &continuationIdentities{ctx: ctx, authority: a, chain: base.ChainID, base: base, current: base, local: map[string]ContinuationIdentity{}, added: []ContinuationIdentity{}}
}
func (s *continuationIdentities) find(k ContinuationIdentityKey) (ContinuationIdentity, bool, error) {
	if e, ok := s.local[continuationIdentityCode(k)]; ok {
		return e, true, nil
	}
	if s.base.Count == 0 {
		return ContinuationIdentity{}, false, nil
	}
	e, ok, err := s.authority.LookupIdentity(s.ctx, s.chain, s.base, k)
	if err != nil {
		return e, false, err
	}
	if ok && (e.Key != k || !continuationIdentityValid(e)) {
		return e, false, invalid("CONTINUATION_IDENTITY_RESOLVER_INVALID")
	}
	return e, ok, nil
}
func (s *continuationIdentities) issue(e ContinuationIdentity, allowReplay bool) (bool, error) {
	if !continuationIdentityValid(e) {
		return false, invalid("CONTINUATION_IDENTITY_INVALID")
	}
	old, ok, err := s.find(e.Key)
	if err != nil {
		return false, err
	}
	if ok {
		if old.SHA256 != e.SHA256 || !allowReplay {
			return false, invalid("CONTINUATION_IDENTITY_REPLAY_CONFLICT")
		}
		return true, nil
	}
	s.current, err = continuationIdentityAdd(s.current, e)
	if err != nil {
		return false, err
	}
	s.local[continuationIdentityCode(e.Key)] = e
	s.added = append(s.added, e)
	return false, nil
}
func continuationOriginalIdentities(e ContinuationEnvelope, v JournalView) ([]ContinuationIdentity, error) {
	out := []ContinuationIdentity{}
	seen := map[string]ContinuationIdentity{}
	add := func(x ContinuationIdentity) error {
		key := continuationIdentityCode(x.Key)
		if old, ok := seen[key]; ok {
			if old.SHA256 != x.SHA256 {
				return invalid("CONTINUATION_ORIGINAL_IDENTITY_CONFLICT")
			}
			return nil
		}
		if !continuationIdentityValid(x) {
			return invalid("CONTINUATION_IDENTITY_INVALID")
		}
		seen[key] = x
		out = append(out, x)
		return nil
	}
	for _, nonce := range []string{v.Parent.Program.Nonce, v.Authorization.Authorization.Nonce, e.Authorization.Nonce} {
		if err := add(continuationReserved("NONCE", nonce)); err != nil {
			return nil, err
		}
	}
	for _, r := range v.Records {
		if r.Kind == JournalPreparing && r.Command != nil {
			c := preparationBase(*r.Command)
			h := Digest(c)
			for _, k := range []ContinuationIdentityKey{{"COMMAND_ID", c.ID}, {"OPERATION_ID", c.OperationID}, {"COMMAND_KEY", c.IdempotencyKey}} {
				if err := add(ContinuationIdentity{k, h}); err != nil {
					return nil, err
				}
			}
		}
		if r.Command != nil {
			c := r.Command
			if c.Forward != nil {
				if err := add(continuationReserved("SIGNED_ID", c.Forward.Child.ID)); err != nil {
					return nil, err
				}
				if err := add(continuationReserved("NONCE", c.Forward.Child.Nonce)); err != nil {
					return nil, err
				}
			}
			if c.Recovery != nil {
				if err := add(continuationReserved("SIGNED_ID", c.Recovery.Recovery.ID)); err != nil {
					return nil, err
				}
				if err := add(continuationReserved("NONCE", c.Recovery.Recovery.Nonce)); err != nil {
					return nil, err
				}
			}
		}
		if r.GitRepair != nil {
			if err := add(continuationReserved("SIGNED_ID", r.GitRepair.Repair.ID)); err != nil {
				return nil, err
			}
			if err := add(continuationReserved("NONCE", r.GitRepair.Repair.Nonce)); err != nil {
				return nil, err
			}
		}
		if r.Receipt != nil {
			h := Digest(r.Receipt.Receipt)
			for _, k := range []ContinuationIdentityKey{{"RECEIPT_ID", r.Receipt.Receipt.ID}, {"RECEIPT_KEY", r.Receipt.Receipt.IdempotencyKey}} {
				if err := add(ContinuationIdentity{k, h}); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}
