// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io"
	"os"

	"github.com/policylabs/collector/statement/intoto"
	"github.com/policylabs/signer"
	soptions "github.com/policylabs/signer/options"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
	"github.com/policylabs/policy/predicate"
)

// NewSigner returns a policy signer with the specified options
func NewSigner(funcs ...options.SignerOptFn) *Signer {
	opts := options.DefaultSignerOptions
	for _, fn := range funcs {
		fn(&opts)
	}
	return &Signer{
		Options: opts,
	}
}

// Signer is the policy material signer: a Policy, a PolicySet or a
// PolicyGroup. Signing is done by wrapping the material in an in-toto
// statement through the predicate/* wrappers, which give it the kind's
// predicate type, before passing it to the sigstore signer.
type Signer struct {
	Options options.SignerOptions
}

// Statement wraps raw policy material of any kind in the in-toto statement
// that gets signed: the predicate is the material, the predicate type the
// kind's (predicate.PolicyPredicateType, PolicySetPredicateType,
// PolicyGroupPredicateType).
func (ps *Signer) Statement(data []byte) (*intoto.Statement, error) {
	set, pcy, grp, _, err := NewParser().ParseVerifyPolicyOrSetOrGroup(data, options.WithVerifySignatures(false))
	if err != nil {
		return nil, fmt.Errorf("parsing policy material: %w", err)
	}

	switch m := PolicyOrSetOrGroup(set, pcy, grp).(type) {
	case *v1.PolicySet:
		return intoto.NewStatement(intoto.WithPredicate(&predicate.PolicySet{Parsed: m})), nil
	case *v1.Policy:
		return intoto.NewStatement(intoto.WithPredicate(&predicate.Policy{Parsed: m})), nil
	case *v1.PolicyGroup:
		return intoto.NewStatement(intoto.WithPredicate(&predicate.PolicyGroup{Parsed: m})), nil
	default:
		return nil, fmt.Errorf("unknown policy material %T", m)
	}
}

// SignPolicyData signs raw policy material of any kind.
func (ps *Signer) SignPolicyData(data []byte, w io.Writer, funcs ...options.SignerOptFn) error {
	statement, err := ps.Statement(data)
	if err != nil {
		return err
	}

	stmtJson, err := statement.ToJson()
	if err != nil {
		return fmt.Errorf("marshaling statement to JSON: %w", err)
	}

	// OK, data is valid, sign it.
	bundle, err := signer.NewSigner().SignStatementBundle(
		stmtJson, soptions.WithPayloadType("application/vnd.in-toto+json"),
	)
	if err != nil {
		return fmt.Errorf("signing policy material: %w", err)
	}

	jsonData, err := protojson.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshaling signed policy: %w", err)
	}

	if _, err := w.Write(jsonData); err != nil {
		return fmt.Errorf("writing JSON data to writer: %w", err)
	}

	return nil
}

// SignBundleToFile signs a policy file and writes it to a filename derived from the original.
func (ps *Signer) SignPolicyFile(path string, w io.Writer, funcs ...options.SignerOptFn) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading policy data: %w", err)
	}

	return ps.SignPolicyData(data, w, funcs...)
}
