package gateway

import (
	"context"
	"sync"
	"testing"
	"time"
)

type concurrentProver struct {
	firstDiff  chan struct{}
	secondDiff chan struct{}
	once       sync.Once
}

func (p *concurrentProver) Check(_ context.Context, raw []byte) (CheckReport, error) {
	ir, err := ParseIR(raw)
	return okReport(ir.Name, ir.Name), err
}

func (p *concurrentProver) Diff(_ context.Context, old, next []byte) (DiffReport, error) {
	from, _ := ParseIR(old)
	to, _ := ParseIR(next)
	if to.Name == "v2" {
		p.once.Do(func() { close(p.firstDiff) })
		// An unsafe implementation lets v3 compare against v1 concurrently.
		// With serialized proposals, wait briefly, then let v2 activate first.
		select {
		case <-p.secondDiff:
		case <-time.After(100 * time.Millisecond):
		}
	} else {
		close(p.secondDiff)
	}
	return DiffReport{FromDigest: from.Name, ToDigest: to.Name, NewlyAllowed: 1, Fingerprint: from.Name + "-" + to.Name}, nil
}

func TestConcurrentProposalsCannotReuseAnObsoleteBaseApproval(t *testing.T) {
	audit, _ := OpenAudit("")
	prover := &concurrentProver{firstDiff: make(chan struct{}), secondDiff: make(chan struct{})}
	key := []byte("test-approval-key")
	g := &Gate{Prover: prover, ApprovalKey: key, Audit: audit}
	if _, err := g.Propose(context.Background(), policy("v1"), ""); err != nil {
		t.Fatal(err)
	}
	approve := func(next string) string {
		return ApprovalToken(key, DiffReport{FromDigest: "v1", ToDigest: next, NewlyAllowed: 1, Fingerprint: "v1-" + next})
	}
	first := make(chan error, 1)
	go func() { _, err := g.Propose(context.Background(), policy("v2"), approve("v2")); first <- err }()
	<-prover.firstDiff
	second := make(chan error, 1)
	go func() { _, err := g.Propose(context.Background(), policy("v3"), approve("v3")); second <- err }()
	if err := <-first; err != nil {
		t.Fatalf("first approved proposal failed: %v", err)
	}
	if err := <-second; err == nil {
		t.Fatal("accepted v1-to-v3 approval after v2 became active")
	}
	if g.Active().Digest != "v2" {
		t.Fatalf("active digest %q, want v2", g.Active().Digest)
	}
	if len(audit.Mem) != 3 || audit.Mem[1].From != "v1" || audit.Mem[2].From != "v2" || audit.Mem[2].Event != "rejected" {
		t.Fatalf("audit does not reflect the serialized transitions: %+v", audit.Mem)
	}
}
