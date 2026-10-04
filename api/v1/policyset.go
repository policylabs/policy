// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func (set *PolicySet) Validate() error {
	// TODO(puerco): Implement with learnings from building this
	// Rules:
	//   Check if same uri has different hashes
	//   Check for same version in same uri
	//   Check all IDs are not repeated
	//
	// Post rules:
	//   Remote ID is not the reference id

	// TODO: Check all IDS are unique (including policy set, policies and groups)
	errs := []error{}
	for key, def := range set.GetCommon().GetContext() {
		if err := def.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("invalid common context definition for %q: %w", key, err))
		}
	}
	for _, p := range set.GetPolicies() {
		if err := p.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, g := range set.GetGroups() {
		if err := g.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (set *PolicySet) SetType(attestation.PredicateType) error {
	return nil
}

func (set *PolicySet) GetType() attestation.PredicateType {
	return attestation.PredicateType("") // TODO: Predicate type
}

// SetVerification gets the signature verification data from the envelope
// parser before discarding the envelope. This is supposed the be stored
// for later retrieval.
// Note: Currently NOOP.
func (set *PolicySet) SetVerification(attestation.Verification) {
}

// GetVerification returns the signature verification generated from the
// envelope parser. The verification may contain details about the integrity,
// identity and signature guarding the PolicySet.
func (set *PolicySet) GetVerification() attestation.Verification {
	return nil
}

// GetParsed returns the PolicySet go struct.
func (set *PolicySet) GetParsed() any {
	return set
}

// GetData returns the policy set data marshaled as json.
func (set *PolicySet) GetData() []byte {
	data, err := protojson.Marshal(set)
	if err != nil {
		return nil
	}
	return data
}

// ContextMap compiles the context data values into a map, filling the fields
// with their defaults when needed. Entries whose value is resolved dynamically
// via an `expression` are skipped: they cannot be known without an evaluator
// and an evaluation context.
func (s *PolicySet) ContextMap() map[string]any {
	ret := map[string]any{}
	for label, value := range s.GetCommon().GetContext() {
		if value.GetExpression() != "" {
			continue
		}
		if value.Value != nil {
			ret[label] = value.Value.AsInterface()
		} else {
			ret[label] = value.Default.AsInterface()
		}
	}
	return ret
}

// PublicKeys returns any public keys defined in the policy identities
func (s *PolicySet) PublicKeys() ([]key.PublicKeyProvider, error) {
	keys := []key.PublicKeyProvider{}
	for _, id := range s.GetCommon().GetIdentities() {
		k, err := id.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		if k != nil {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// GetOrigin returns the coordinates where the predicate data originated from.
func (s *PolicySet) GetOrigin() attestation.Subject {
	if s.GetMeta() == nil {
		return nil
	}
	return s.GetMeta().GetOrigin()
}

// SetOrigin sets the origin of the policy. It is designed to match the signature
// of the attestation.Predicate method, but if the argument is a resource descriptor,
// then we will clone it and use its value.
func (s *PolicySet) SetOrigin(origin attestation.Subject) {
	if s.GetMeta() == nil {
		s.Meta = &PolicySetMeta{}
	}

	rd, ok := origin.(*intoto.ResourceDescriptor)
	if ok {
		msg := proto.Clone(rd)
		nrd, ok := msg.(*intoto.ResourceDescriptor)
		if ok {
			s.Meta.Origin = nrd
			return
		}
	}

	s.Meta.Origin = &intoto.ResourceDescriptor{
		Name:   origin.GetName(),
		Uri:    origin.GetUri(),
		Digest: origin.GetDigest(),
	}
}
