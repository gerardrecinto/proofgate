// proofgate-gateway serves decisions and gates policy changes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gerardrecinto/proofgate/gateway"
)

const usage = `usage:
  proofgate-gateway serve   -prover BIN -bundle policy.json [-addr :8080] [-audit audit.jsonl] [-approval-key-file F]
  proofgate-gateway approve -prover BIN -key-file F old.json new.json
  proofgate-gateway verify-audit audit.jsonl`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "approve":
		err = approve(os.Args[2:])
	case "verify-audit":
		err = verifyAudit(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "proofgate-gateway:", err)
		os.Exit(1)
	}
}

func readKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	return []byte(strings.TrimSpace(string(b))), err
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	prover := fs.String("prover", "proofgate", "path to the proofgate binary")
	bundle := fs.String("bundle", "", "initial policy.json")
	auditPath := fs.String("audit", "", "hash-chained audit log (memory only if empty)")
	keyFile := fs.String("approval-key-file", "", "HMAC key for approvals (widening is refused without it)")
	fs.Parse(args)

	key, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	audit, err := gateway.OpenAudit(*auditPath)
	if err != nil {
		return err
	}
	defer audit.Close()
	g := &gateway.Gate{Prover: gateway.ExecProver{Bin: *prover, Timeout: 10 * time.Second}, ApprovalKey: key, Audit: audit}

	if *bundle != "" {
		raw, err := os.ReadFile(*bundle)
		if err != nil {
			return err
		}
		b, err := g.Propose(context.Background(), raw, "")
		if err != nil {
			return fmt.Errorf("initial bundle refused: %w", err)
		}
		log.Printf("active bundle %s (%s)", b.Name, b.Digest[:12])
	}

	srv := gateway.NewServer(*addr, g.Handler())
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	log.Printf("listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func approve(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	prover := fs.String("prover", "proofgate", "path to the proofgate binary")
	keyFile := fs.String("key-file", "", "HMAC key file")
	fs.Parse(args)
	if fs.NArg() != 2 || *keyFile == "" {
		return fmt.Errorf("need -key-file and two policy files\n%s", usage)
	}
	key, err := readKey(*keyFile)
	if err != nil || len(key) == 0 {
		return fmt.Errorf("cannot read key: %v", err)
	}
	oldRaw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	newRaw, err := os.ReadFile(fs.Arg(1))
	if err != nil {
		return err
	}
	diff, err := gateway.ExecProver{Bin: *prover, Timeout: 10 * time.Second}.Diff(context.Background(), oldRaw, newRaw)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "approving exactly: %d newly allowed, %d newly denied (fingerprint %s)\n", diff.NewlyAllowed, diff.NewlyDenied, diff.Fingerprint[:12])
	fmt.Println(gateway.ApprovalToken(key, diff))
	return nil
}

func verifyAudit(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf(usage)
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	n, last, err := gateway.VerifyChain(f)
	if err != nil {
		return err
	}
	fmt.Printf("%d entries, chain intact, head %s\n", n, last[:12])
	return nil
}
