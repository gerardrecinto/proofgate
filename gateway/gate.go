package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// Bundle is an activated policy.
type Bundle struct {
	Digest string
	Name   string
	Raw    []byte
	Eval   *Evaluator
}

// Gate decides whether a candidate policy may replace the active one.
type Gate struct {
	Prover      Prover
	ApprovalKey []byte
	Audit       *AuditLog
	active      atomic.Pointer[Bundle]
}

// Rejection says why a bundle was refused. Report carries the evidence.
type Rejection struct {
	Reason string
	Report any
}

func (r *Rejection) Error() string { return r.Reason }

func (g *Gate) Active() *Bundle { return g.active.Load() }

// Propose proves the candidate, compares it with the active policy, and swaps it in only if
// every invariant holds and any widening of access carries a valid approval.
func (g *Gate) Propose(ctx context.Context, candidate []byte, approval string) (*Bundle, error) {
	reject := func(b *Bundle, to string, reason string, report any, widened uint64) error {
		from := ""
		if b != nil {
			from = b.Digest
		}
		if _, err := g.Audit.Append(AuditEntry{Event: "rejected", From: from, To: to, Reason: reason, Widened: widened}); err != nil {
			return err
		}
		return &Rejection{Reason: reason, Report: report}
	}

	ir, err := ParseIR(candidate)
	if err != nil {
		return nil, &Rejection{Reason: err.Error()}
	}
	check, err := g.Prover.Check(ctx, candidate)
	if err != nil {
		return nil, &Rejection{Reason: err.Error()}
	}
	cur := g.active.Load()
	if !check.OK {
		return nil, reject(cur, check.Digest, "an invariant does not hold", check, 0)
	}
	ev, err := NewEvaluator(ir)
	if err != nil {
		return nil, &Rejection{Reason: err.Error()}
	}

	entry := AuditEntry{Event: "activated", To: check.Digest}
	if cur != nil {
		entry.From = cur.Digest
		diff, err := g.Prover.Diff(ctx, cur.Raw, candidate)
		if err != nil {
			return nil, &Rejection{Reason: err.Error()}
		}
		entry.Fingerprint, entry.Widened = diff.Fingerprint, diff.NewlyAllowed
		if diff.NewlyAllowed > 0 {
			if !ValidApproval(g.ApprovalKey, diff, approval) {
				return nil, reject(cur, check.Digest, fmt.Sprintf("allows %d requests the active policy denies and carries no valid approval for this exact change", diff.NewlyAllowed), diff, diff.NewlyAllowed)
			}
			entry.Approved = true
		}
	}
	if _, err := g.Audit.Append(entry); err != nil {
		return nil, errors.New("audit log write failed, bundle not activated: " + err.Error())
	}
	b := &Bundle{Digest: check.Digest, Name: check.Name, Raw: candidate, Eval: ev}
	g.active.Store(b)
	return b, nil
}
