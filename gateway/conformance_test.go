package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Every request in the example policies gets the same answer from this evaluator as from the
// Rust one. Run with PROOFGATE_BIN pointing at the built binary; CI always does.
func TestEvaluatorMatchesRustOverEveryRequest(t *testing.T) {
	bin := os.Getenv("PROOFGATE_BIN")
	if bin == "" {
		t.Skip("PROOFGATE_BIN not set")
	}
	files, _ := filepath.Glob("../examples/deploys/*.json")
	if len(files) == 0 {
		t.Fatal("no compiled example policies found in ../examples/deploys")
	}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := ParseIR(raw)
		if err != nil {
			t.Fatal(err)
		}
		ev, err := NewEvaluator(ir)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "vectors", file)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		n := 0
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			var v struct {
				Request map[string]string `json:"request"`
				Effect  string            `json:"effect"`
				Rule    string            `json:"rule"`
			}
			if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
				t.Fatal(err)
			}
			got, err := ev.Decide(v.Request)
			if err != nil || got.Effect != v.Effect || got.Rule != v.Rule {
				t.Fatalf("%s %v: go says %v (%v), rust says %s %s", file, v.Request, got, err, v.Effect, v.Rule)
			}
			n++
		}
		if err := cmd.Wait(); err != nil || n == 0 {
			t.Fatalf("%s: vectors failed after %d: %v", file, n, err)
		}
		t.Logf("%s: %d requests agree", filepath.Base(file), n)
	}
}

// The real prover and the real gate, end to end, on the example policies.
func TestGateWithRealProver(t *testing.T) {
	bin := os.Getenv("PROOFGATE_BIN")
	if bin == "" {
		t.Skip("PROOFGATE_BIN not set")
	}
	read := func(name string) []byte {
		b, err := os.ReadFile("../examples/deploys/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	audit, _ := OpenAudit("")
	g := &Gate{Prover: ExecProver{Bin: bin}, ApprovalKey: []byte("k"), Audit: audit}
	ctx := context.Background()

	if _, err := g.Propose(ctx, read("policy"), ""); err != nil {
		t.Fatalf("v1: %v", err)
	}
	if _, err := g.Propose(ctx, read("policy_broken"), ""); err == nil {
		t.Fatal("policy that breaks an invariant was activated")
	}
	if _, err := g.Propose(ctx, read("policy_v2"), ""); err == nil {
		t.Fatal("silent widening was activated")
	}
	diff, err := g.Prover.Diff(ctx, read("policy"), read("policy_v2"))
	if err != nil {
		t.Fatal(err)
	}
	if diff.NewlyAllowed != 7 {
		t.Fatalf("want 7 newly allowed, got %d", diff.NewlyAllowed)
	}
	if _, err := g.Propose(ctx, read("policy_v2"), ApprovalToken([]byte("k"), diff)); err != nil {
		t.Fatalf("approved widening refused: %v", err)
	}
}
