package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// CheckReport is the part of `proofgate check --json` the gateway acts on.
type CheckReport struct {
	Name       string            `json:"name"`
	Digest     string            `json:"digest"`
	OK         bool              `json:"ok"`
	Invariants []InvariantResult `json:"invariants"`
}

type InvariantResult struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Holds       bool   `json:"holds"`
}

// DiffReport is the part of `proofgate diff --json` the gateway acts on.
type DiffReport struct {
	FromDigest   string            `json:"from_digest"`
	ToDigest     string            `json:"to_digest"`
	NewlyAllowed uint64            `json:"newly_allowed"`
	NewlyDenied  uint64            `json:"newly_denied"`
	Fingerprint  string            `json:"fingerprint"`
	Changes      []json.RawMessage `json:"changes"`
}

// Prover proves things about policies. The production implementation runs the Rust binary.
type Prover interface {
	Check(ctx context.Context, policy []byte) (CheckReport, error)
	Diff(ctx context.Context, from, to []byte) (DiffReport, error)
}

// ExecProver shells out to the `proofgate` binary built from ./core.
type ExecProver struct {
	Bin     string
	Timeout time.Duration
}

func (p ExecProver) run(ctx context.Context, out any, args []string, files ...[]byte) error {
	if p.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.Timeout)
		defer cancel()
	}
	dir, err := os.MkdirTemp("", "proofgate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	full := []string{args[0]}
	for i, data := range files {
		path := filepath.Join(dir, fmt.Sprintf("p%d.json", i))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		full = append(full, path)
	}
	full = append(full, args[1:]...)
	cmd := exec.CommandContext(ctx, p.Bin, full...)
	stdout, err := cmd.Output()
	// Exit 1 means "analysis ran, finding reported" and still prints JSON.
	var exit *exec.ExitError
	if err != nil && !(asExit(err, &exit) && exit.ExitCode() == 1) {
		msg := ""
		if asExit(err, &exit) {
			msg = string(exit.Stderr)
		}
		return fmt.Errorf("prover: %w %s", err, msg)
	}
	return json.Unmarshal(stdout, out)
}

func asExit(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func (p ExecProver) Check(ctx context.Context, policy []byte) (CheckReport, error) {
	var r CheckReport
	err := p.run(ctx, &r, []string{"check", "--json"}, policy)
	return r, err
}

func (p ExecProver) Diff(ctx context.Context, from, to []byte) (DiffReport, error) {
	var r DiffReport
	err := p.run(ctx, &r, []string{"diff", "--json"}, from, to)
	return r, err
}
