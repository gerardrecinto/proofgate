package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeProver lets tests script what the Rust prover would report.
type fakeProver struct {
	check map[string]CheckReport // keyed by policy name
	diff  DiffReport
}

func (f fakeProver) Check(_ context.Context, p []byte) (CheckReport, error) {
	ir, err := ParseIR(p)
	if err != nil {
		return CheckReport{}, err
	}
	return f.check[ir.Name], nil
}

func (f fakeProver) Diff(context.Context, []byte, []byte) (DiffReport, error) { return f.diff, nil }

func policy(name string) []byte {
	return []byte(`{"version":1,"name":"` + name + `","dimensions":[{"name":"env","values":["dev","prod"]},{"name":"role","values":["sre","eng"]}],
	"rules":[{"id":"sre","effect":"allow","when":{"role":["sre"]}},{"id":"dev","effect":"allow","when":{"env":["dev"]}}]}`)
}

func newGate(t *testing.T, f fakeProver, key string) *Gate {
	t.Helper()
	a, _ := OpenAudit("")
	return &Gate{Prover: f, ApprovalKey: []byte(key), Audit: a}
}

func okReport(name, digest string) CheckReport {
	return CheckReport{Name: name, Digest: digest, OK: true}
}

func TestEvaluatorFirstMatchWins(t *testing.T) {
	ir, _ := ParseIR(policy("p"))
	ev, err := NewEvaluator(ir)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		req  map[string]string
		want Decision
	}{
		{map[string]string{"env": "prod", "role": "sre"}, Decision{"allow", "sre"}},
		{map[string]string{"env": "dev", "role": "eng"}, Decision{"allow", "dev"}},
		{map[string]string{"env": "prod", "role": "eng"}, Decision{"deny", "default deny"}},
	}
	for _, c := range cases {
		got, err := ev.Decide(c.req)
		if err != nil || got != c.want {
			t.Errorf("%v: got %v %v, want %v", c.req, got, err, c.want)
		}
	}
}

func TestEvaluatorRejectsMalformedRequests(t *testing.T) {
	ir, _ := ParseIR(policy("p"))
	ev, _ := NewEvaluator(ir)
	for _, req := range []map[string]string{
		{"env": "prod"},
		{"env": "nope", "role": "sre"},
		{"env": "prod", "role": "sre", "extra": "x"},
	} {
		if _, err := ev.Decide(req); err == nil {
			t.Errorf("%v should be refused", req)
		}
	}
}

func TestFirstBundleNeedsOnlyInvariants(t *testing.T) {
	g := newGate(t, fakeProver{check: map[string]CheckReport{"v1": okReport("v1", "d1")}}, "")
	if _, err := g.Propose(context.Background(), policy("v1"), ""); err != nil {
		t.Fatal(err)
	}
	if g.Active().Digest != "d1" {
		t.Fatal("bundle not active")
	}
}

func TestBrokenInvariantIsRefusedAndKeepsOldBundle(t *testing.T) {
	f := fakeProver{check: map[string]CheckReport{
		"v1":  okReport("v1", "d1"),
		"bad": {Name: "bad", Digest: "d2", OK: false, Invariants: []InvariantResult{{ID: "never_prod", Holds: false}}},
	}}
	g := newGate(t, f, "")
	g.Propose(context.Background(), policy("v1"), "")
	_, err := g.Propose(context.Background(), policy("bad"), "")
	var rej *Rejection
	if !errors.As(err, &rej) || !strings.Contains(rej.Reason, "invariant") {
		t.Fatalf("want invariant rejection, got %v", err)
	}
	if g.Active().Digest != "d1" {
		t.Fatal("rejected bundle replaced the active one")
	}
}

func TestWideningNeedsAnApprovalForThatExactChange(t *testing.T) {
	diff := DiffReport{FromDigest: "d1", ToDigest: "d2", NewlyAllowed: 3, Fingerprint: "fp"}
	f := fakeProver{check: map[string]CheckReport{"v1": okReport("v1", "d1"), "v2": okReport("v2", "d2")}, diff: diff}
	key := "secret"

	t.Run("no approval", func(t *testing.T) {
		g := newGate(t, f, key)
		g.Propose(context.Background(), policy("v1"), "")
		if _, err := g.Propose(context.Background(), policy("v2"), ""); err == nil {
			t.Fatal("widening passed without approval")
		}
		if g.Active().Digest != "d1" {
			t.Fatal("active bundle changed")
		}
	})
	t.Run("token for a different change", func(t *testing.T) {
		g := newGate(t, f, key)
		g.Propose(context.Background(), policy("v1"), "")
		other := diff
		other.Fingerprint = "someone else's diff"
		if _, err := g.Propose(context.Background(), policy("v2"), ApprovalToken([]byte(key), other)); err == nil {
			t.Fatal("approval for another change was accepted")
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		g := newGate(t, f, key)
		g.Propose(context.Background(), policy("v1"), "")
		if _, err := g.Propose(context.Background(), policy("v2"), ApprovalToken([]byte("guess"), diff)); err == nil {
			t.Fatal("token from the wrong key was accepted")
		}
	})
	t.Run("no key configured", func(t *testing.T) {
		g := newGate(t, f, "")
		g.Propose(context.Background(), policy("v1"), "")
		if _, err := g.Propose(context.Background(), policy("v2"), ApprovalToken(nil, diff)); err == nil {
			t.Fatal("widening passed with no approval key configured")
		}
	})
	t.Run("valid approval", func(t *testing.T) {
		g := newGate(t, f, key)
		g.Propose(context.Background(), policy("v1"), "")
		if _, err := g.Propose(context.Background(), policy("v2"), ApprovalToken([]byte(key), diff)); err != nil {
			t.Fatal(err)
		}
		if g.Active().Digest != "d2" {
			t.Fatal("approved bundle not active")
		}
	})
}

func TestNarrowingNeedsNoApproval(t *testing.T) {
	f := fakeProver{
		check: map[string]CheckReport{"v1": okReport("v1", "d1"), "v2": okReport("v2", "d2")},
		diff:  DiffReport{FromDigest: "d1", ToDigest: "d2", NewlyDenied: 5},
	}
	g := newGate(t, f, "")
	g.Propose(context.Background(), policy("v1"), "")
	if _, err := g.Propose(context.Background(), policy("v2"), ""); err != nil {
		t.Fatal(err)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	a, _ := OpenAudit("")
	for _, e := range []AuditEntry{{Event: "activated", To: "d1"}, {Event: "rejected", From: "d1", To: "d2", Reason: "x"}, {Event: "activated", From: "d1", To: "d3"}} {
		a.Append(e)
	}
	var buf bytes.Buffer
	for _, e := range a.Mem {
		b, _ := json.Marshal(e)
		buf.Write(append(b, '\n'))
	}
	if n, _, err := VerifyChain(bytes.NewReader(buf.Bytes())); err != nil || n != 3 {
		t.Fatalf("intact chain failed: %d %v", n, err)
	}
	tampered := strings.Replace(buf.String(), `"reason":"x"`, `"reason":"y"`, 1)
	if _, _, err := VerifyChain(strings.NewReader(tampered)); err == nil {
		t.Fatal("edited entry not detected")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	dropped := strings.Join([]string{lines[0], lines[2]}, "\n")
	if _, _, err := VerifyChain(strings.NewReader(dropped)); err == nil {
		t.Fatal("removed entry not detected")
	}
}

func TestAuditSurvivesRestart(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	a, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	a.Append(AuditEntry{Event: "activated", To: "d1"})
	a.Close()
	b, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := b.Append(AuditEntry{Event: "activated", To: "d2"})
	b.Close()
	if e.Seq != 2 {
		t.Fatalf("seq %d after restart", e.Seq)
	}
}

func TestHTTP(t *testing.T) {
	f := fakeProver{check: map[string]CheckReport{"v1": okReport("v1", "d1")}}
	g := newGate(t, f, "")
	srv := httptest.NewServer(g.Handler())
	defer srv.Close()

	get := func(path string) int {
		r, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if get("/healthz") != http.StatusServiceUnavailable {
		t.Error("healthz should fail with no bundle")
	}

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/v1/bundle", bytes.NewReader(policy("v1")))
	if r, err := http.DefaultClient.Do(req); err != nil || r.StatusCode != 200 {
		t.Fatalf("put bundle: %v %v", r, err)
	}
	if get("/healthz") != 200 || get("/v1/bundle") != 200 {
		t.Error("expected healthy with a bundle")
	}

	decide := func(body string) (int, map[string]any) {
		r, err := http.Post(srv.URL+"/v1/decide", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		json.NewDecoder(r.Body).Decode(&out)
		return r.StatusCode, out
	}
	if code, out := decide(`{"request":{"env":"prod","role":"sre"}}`); code != 200 || out["effect"] != "allow" || out["rule"] != "sre" {
		t.Errorf("decide: %d %v", code, out)
	}
	if code, _ := decide(`{"request":{"env":"prod"}}`); code != 400 {
		t.Errorf("incomplete request should be 400, got %d", code)
	}
	if code, _ := decide(`not json`); code != 400 {
		t.Errorf("bad body should be 400, got %d", code)
	}
}
