// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package predicate

import (
	"encoding/json"

	"github.com/policylabs/attestation"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/policylabs/policy/api/v1"
)

const PolicyPredicateType attestation.PredicateType = "https://carabiner.dev/ampel/policy/v0"

// Policy (or rather predicate.Policy) is a wrapper around the policy proto
// message that implements the ampel attestation predicate interface.
type Policy struct {
	Parsed       *v1.Policy
	Data         []byte
	verification attestation.Verification
}

// GetOrigin calls the underlying method of the same name
func (p *Policy) GetOrigin() attestation.Subject {
	if p.Parsed == nil {
		return nil
	}

	return p.Parsed.GetOrigin()
}

// SetOrigin calls the underlting method of the same name
func (p *Policy) SetOrigin(origin attestation.Subject) {
	if p.Parsed == nil {
		return
	}
	p.Parsed.SetOrigin(origin)
}

func (p *Policy) SetType(attestation.PredicateType) error {
	return nil
}

func (p *Policy) GetType() attestation.PredicateType {
	return PolicyPredicateType
}

// SetVerification gets the signature verification data from the envelope
// parser before discarding the envelope. This is supposed the be stored
// for later retrieval.
func (p *Policy) SetVerification(verification attestation.Verification) {
	p.verification = verification
}

// GetVerification returns the signature verification generated from the
// envelope parser. The verification may contain details about the integrity,
// identity and signature guarding the PolicySet.
func (p *Policy) GetVerification() attestation.Verification {
	return p.verification
}

// GetParsed returns the Go policy object.
func (p *Policy) GetParsed() any {
	return p.Parsed
}

// GetData returns the policy data serialized as JSON.
func (p *Policy) GetData() []byte {
	if p.Data != nil {
		return p.Data
	}

	data, err := protojson.Marshal(p.Parsed)
	if err != nil {
		return nil
	}
	p.Data = data
	return data
}

// MarshalJSON implements the JSON marshaler interface. It reuses any pre
// parsed data already stored in the predicate.
func (p *Policy) MarshalJSON() ([]byte, error) {
	// If the predicate was already marshalled, reuse the output
	if p.Data != nil {
		return p.Data, nil
	}

	// Otherwise, marshal the value
	return json.Marshal(p.Parsed) //nolint:musttag // This has a custom marshaller
}
