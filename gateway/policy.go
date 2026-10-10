// Package gateway enforces Proofgate policies and refuses to activate a policy change
// that breaks an invariant or widens access without an approval bound to that exact change.
package gateway

import (
	"encoding/json"
	"fmt"
	"math/bits"
)

// IR mirrors the JSON the Ruby DSL emits and the Rust prover reads.
type IR struct {
	Version    int         `json:"version"`
	Name       string      `json:"name"`
	Dimensions []Dimension `json:"dimensions"`
	Rules      []IRRule    `json:"rules"`
}

type Dimension struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type IRRule struct {
	ID     string              `json:"id"`
	Effect string              `json:"effect"`
	When   map[string][]string `json:"when"`
}

// Decision is the answer for one request.
type Decision struct {
	Effect string `json:"effect"`
	Rule   string `json:"rule"`
}

// Evaluator answers requests in a few bit operations per rule. It mirrors the Rust
// evaluator exactly, which the conformance test checks over every request.
type Evaluator struct {
	dims  []Dimension
	index map[string]int
	rules []compiled
}

type compiled struct {
	id    string
	allow bool
	masks []uint64 // one per dimension, all ones when the rule does not mention it
}

func ParseIR(data []byte) (*IR, error) {
	var ir IR
	if err := json.Unmarshal(data, &ir); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if ir.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d", ir.Version)
	}
	return &ir, nil
}

// NewEvaluator compiles a policy the prover has already validated.
func NewEvaluator(ir *IR) (*Evaluator, error) {
	e := &Evaluator{dims: ir.Dimensions, index: map[string]int{}}
	for i, d := range ir.Dimensions {
		if len(d.Values) == 0 || len(d.Values) > 64 {
			return nil, fmt.Errorf("dimension %q needs 1 to 64 values", d.Name)
		}
		e.index[d.Name] = i
	}
	for _, r := range ir.Rules {
		c := compiled{id: r.ID, allow: r.Effect == "allow", masks: make([]uint64, len(ir.Dimensions))}
		for i, d := range ir.Dimensions {
			c.masks[i] = fullMask(len(d.Values))
			vals, ok := r.When[d.Name]
			if !ok {
				continue
			}
			var m uint64
			for _, v := range vals {
				bit, found := valueBit(d, v)
				if !found {
					return nil, fmt.Errorf("rule %q: unknown value %q for %q", r.ID, v, d.Name)
				}
				m |= bit
			}
			c.masks[i] = m
		}
		for dim := range r.When {
			if _, ok := e.index[dim]; !ok {
				return nil, fmt.Errorf("rule %q: unknown dimension %q", r.ID, dim)
			}
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

func fullMask(n int) uint64 {
	if n == 64 {
		return ^uint64(0)
	}
	return (uint64(1) << n) - 1
}

func valueBit(d Dimension, v string) (uint64, bool) {
	for i, x := range d.Values {
		if x == v {
			return 1 << i, true
		}
	}
	return 0, false
}

// Decide returns the first matching rule's effect, or deny when none match.
func (e *Evaluator) Decide(request map[string]string) (Decision, error) {
	point := make([]uint64, len(e.dims))
	for i, d := range e.dims {
		v, ok := request[d.Name]
		if !ok {
			return Decision{}, fmt.Errorf("missing dimension %q", d.Name)
		}
		bit, found := valueBit(d, v)
		if !found {
			return Decision{}, fmt.Errorf("unknown value %q for %q", v, d.Name)
		}
		point[i] = bit
	}
	for k := range request {
		if _, ok := e.index[k]; !ok {
			return Decision{}, fmt.Errorf("unknown dimension %q", k)
		}
	}
	for _, r := range e.rules {
		if r.matches(point) {
			effect := "deny"
			if r.allow {
				effect = "allow"
			}
			return Decision{Effect: effect, Rule: r.id}, nil
		}
	}
	return Decision{Effect: "deny", Rule: "default deny"}, nil
}

func (r compiled) matches(point []uint64) bool {
	for i, m := range r.masks {
		if bits.OnesCount64(m&point[i]) == 0 {
			return false
		}
	}
	return true
}
