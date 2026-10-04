// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package predicate

import (
	"encoding/json"

	"github.com/policylabs/attestation"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/policylabs/policy/api/v1"
)

const PolicyGroupPredicateType attestation.PredicateType = "https://carabiner.dev/ampel/policygroup/v0"

// Policy (or rather predicate.Policy) is a wrapper around the policy proto
// message that implements the ampel attestation predicate interface.
type PolicyGroup struct {
	Parsed       *v1.PolicyGroup
	Data         []byte
	verification attestation.Verification
}

// GetOrigin calls the underlying method of the same name
func (grp *PolicyGroup) GetOrigin() attestation.Subject {
	if grp.Parsed == nil {
		return nil
	}

	return grp.Parsed.GetOrigin()
}

// SetOrigin calls the underlying method of the same name
func (grp *PolicyGroup) SetOrigin(origin attestation.Subject) {
	if grp.Parsed == nil {
		return
	}
	grp.Parsed.SetOrigin(origin)
}

// GetVerification returns the signature verification generated from the
// envelope parser. The verification may contain details about the integrity,
// identity and signature guarding the PolicyGroup.
func (grp *PolicyGroup) GetVerification() attestation.Verification {
	return grp.verification
}

// SetVerification gets the signature verification data from the envelope
// parser before discarding the envelope. This is supposed the be stored
// for later retrieval.
func (grp *PolicyGroup) SetVerification(verification attestation.Verification) {
	grp.verification = verification
}

// GetParsed returns the Go policy object.
func (grp *PolicyGroup) GetParsed() any {
	return grp.Parsed
}

// GetData returns the policy data serialized as JSON.
func (grp *PolicyGroup) GetData() []byte {
	if grp.Data != nil {
		return grp.Data
	}

	data, err := protojson.Marshal(grp.Parsed)
	if err != nil {
		return nil
	}
	grp.Data = data
	return data
}

// MarshalJSON implements the JSON marshaler interface. It reuses any pre
// parsed data already stored in the predicate.
func (grp *PolicyGroup) MarshalJSON() ([]byte, error) {
	// If the predicate was already marshalled, reuse the output
	if grp.Data != nil {
		return grp.Data, nil
	}

	// Otherwise, marshal the value
	return json.Marshal(grp.Parsed) //nolint:musttag // This has a custom marshaller
}

func (grp *PolicyGroup) SetType(attestation.PredicateType) error {
	return nil
}

func (grp *PolicyGroup) GetType() attestation.PredicateType {
	return PolicyPredicateType
}
