package gateway

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// AuditEntry is one line of the log. Each entry commits to the one before it, so removing or
// editing any line breaks every hash after it.
type AuditEntry struct {
	Seq         uint64 `json:"seq"`
	Time        string `json:"time"`
	Event       string `json:"event"` // activated or rejected
	From        string `json:"from,omitempty"`
	To          string `json:"to"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Widened     uint64 `json:"widened,omitempty"`
	Approved    bool   `json:"approved,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Prev        string `json:"prev"`
	Hash        string `json:"hash"`
}

func entryHash(e AuditEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AuditLog appends hash-chained entries to a file, or keeps them in memory when path is empty.
type AuditLog struct {
	mu   sync.Mutex
	f    *os.File
	seq  uint64
	last string
	Mem  []AuditEntry
}

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

func OpenAudit(path string) (*AuditLog, error) {
	a := &AuditLog{last: genesis}
	if path == "" {
		return a, nil
	}
	if f, err := os.Open(path); err == nil {
		n, last, verr := VerifyChain(f)
		f.Close()
		if verr != nil {
			return nil, fmt.Errorf("audit log %s is corrupt: %w", path, verr)
		}
		a.seq, a.last = n, last
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	a.f = f
	return a, nil
}

func (a *AuditLog) Append(e AuditEntry) (AuditEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	e.Seq, e.Prev, e.Time = a.seq, a.last, time.Now().UTC().Format(time.RFC3339)
	e.Hash = entryHash(e)
	if a.f != nil {
		b, _ := json.Marshal(e)
		if _, err := a.f.Write(append(b, '\n')); err != nil {
			a.seq--
			return e, err
		}
		if err := a.f.Sync(); err != nil {
			return e, err
		}
	} else {
		a.Mem = append(a.Mem, e)
	}
	a.last = e.Hash
	return e, nil
}

func (a *AuditLog) Close() error {
	if a.f != nil {
		return a.f.Close()
	}
	return nil
}

// VerifyChain checks every hash and link, returning the entry count and the last hash.
func VerifyChain(r io.Reader) (uint64, string, error) {
	prev, n := genesis, uint64(0)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, prev, fmt.Errorf("line %d: %w", n+1, err)
		}
		if e.Seq != n+1 || e.Prev != prev || e.Hash != entryHash(e) {
			return n, prev, fmt.Errorf("entry %d does not match the chain", n+1)
		}
		prev, n = e.Hash, n+1
	}
	return n, prev, sc.Err()
}
