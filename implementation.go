// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"buf.build/go/protovalidate"
	"github.com/carabiner-dev/hasher"
	"github.com/hjson/hjson-go/v4"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/envelope"
	sapi "github.com/policylabs/signer/api/v1"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
)

type parserImplementation interface {
	ParsePolicySet(*options.ParseOptions, []byte) (*v1.PolicySet, attestation.Verification, error)
	ParsePolicy(*options.ParseOptions, []byte) (*v1.Policy, attestation.Verification, error)
	ParsePolicyGroup(*options.ParseOptions, []byte) (*v1.PolicyGroup, attestation.Verification, error)
}

type defaultParserImplementationV1 struct{}

// checkJSONDepth validates that JSON data does not exceed the maximum nesting depth.
// This prevents stack overflow attacks from deeply nested structures.
func checkJSONDepth(data []byte, maxDepth int) (int, error) {
	if maxDepth <= 0 {
		return 0, nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	var depth, maxObserved int

	for {
		token, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			//nolint:nilerr // Invalid JSON will be caught later by the actual parser
			return maxObserved, nil
		}

		switch token {
		case json.Delim('['), json.Delim('{'):
			depth++
			if depth > maxObserved {
				maxObserved = depth
			}
			if depth > maxDepth {
				return maxObserved, options.NewJSONDepthError(maxDepth, depth, "")
			}
		case json.Delim(']'), json.Delim('}'):
			depth--
		}
	}

	return maxObserved, nil
}

// validatePolicySetLimits validates that a PolicySet does not exceed configured limits.
func validatePolicySetLimits(opts *options.ParseOptions, set *v1.PolicySet) error {
	limits := opts.Limits

	// Check policies per set
	if limits.MaxPoliciesPerSet > 0 && len(set.GetPolicies()) > limits.MaxPoliciesPerSet {
		return options.NewCollectionSizeError(
			"policies per set",
			limits.MaxPoliciesPerSet,
			len(set.GetPolicies()),
			set.GetId(),
		)
	}

	// Check groups per set
	if limits.MaxGroupsPerSet > 0 && len(set.GetGroups()) > limits.MaxGroupsPerSet {
		return options.NewCollectionSizeError(
			"groups per set",
			limits.MaxGroupsPerSet,
			len(set.GetGroups()),
			set.GetId(),
		)
	}

	// Validate nested policies
	for i, p := range set.GetPolicies() {
		if err := validatePolicyLimits(opts, p); err != nil {
			return fmt.Errorf("policy #%d: %w", i, err)
		}
	}

	// Validate nested groups
	for i, g := range set.GetGroups() {
		if err := validatePolicyGroupLimits(opts, g); err != nil {
			return fmt.Errorf("group #%d: %w", i, err)
		}
	}

	return nil
}

// validatePolicyLimits validates that a Policy does not exceed configured limits.
func validatePolicyLimits(opts *options.ParseOptions, p *v1.Policy) error {
	limits := opts.Limits

	// Check tenets per policy
	if limits.MaxTenetsPerPolicy > 0 && len(p.GetTenets()) > limits.MaxTenetsPerPolicy {
		return options.NewCollectionSizeError(
			"tenets per policy",
			limits.MaxTenetsPerPolicy,
			len(p.GetTenets()),
			p.GetId(),
		)
	}

	return nil
}

// validatePolicyGroupLimits validates that a PolicyGroup does not exceed configured limits.
func validatePolicyGroupLimits(opts *options.ParseOptions, g *v1.PolicyGroup) error {
	limits := opts.Limits

	// Check blocks per group
	if limits.MaxBlocksPerGroup > 0 && len(g.GetBlocks()) > limits.MaxBlocksPerGroup {
		return options.NewCollectionSizeError(
			"blocks per group",
			limits.MaxBlocksPerGroup,
			len(g.GetBlocks()),
			g.GetId(),
		)
	}

	// Check policies per block and validate nested policies
	for i, block := range g.GetBlocks() {
		if limits.MaxPoliciesPerBlock > 0 && len(block.GetPolicies()) > limits.MaxPoliciesPerBlock {
			return options.NewCollectionSizeError(
				"policies per block",
				limits.MaxPoliciesPerBlock,
				len(block.GetPolicies()),
				fmt.Sprintf("%s/block#%d", g.GetId(), i),
			)
		}

		for j, p := range block.GetPolicies() {
			if err := validatePolicyLimits(opts, p); err != nil {
				return fmt.Errorf("block #%d, policy #%d: %w", i, j, err)
			}
		}
	}

	return nil
}

// normalizeToJSON attempts to parse data as JSON first. If that fails,
// it tries to parse as HJSON and converts it to JSON. This allows transparent
// support for both JSON and HJSON policy formats.
// If maxDepth > 0, it also validates that the JSON depth does not exceed the limit.
func normalizeToJSON(data []byte, maxDepth int) ([]byte, error) {
	// First, try to parse as strict JSON to validate it's well-formed
	var jsonTest any
	if err := json.Unmarshal(data, &jsonTest); err == nil {
		// Data is valid JSON, check depth limit before returning
		if _, err := checkJSONDepth(data, maxDepth); err != nil {
			return nil, err
		}
		return data, nil
	}

	// If JSON parsing failed, try HJSON
	var hjsonData any
	if err := hjson.Unmarshal(data, &hjsonData); err != nil {
		// Neither JSON nor HJSON worked, return original error context
		return nil, fmt.Errorf("failed to parse as JSON or HJSON: %w", err)
	}

	// Convert HJSON-parsed data back to standard JSON
	jsonData, err := json.Marshal(hjsonData)
	if err != nil {
		return nil, fmt.Errorf("converting HJSON to JSON: %w", err)
	}

	// Check depth limit on the normalized JSON
	if _, err := checkJSONDepth(jsonData, maxDepth); err != nil {
		return nil, err
	}

	return jsonData, nil
}

// ParsePolicySet parses a policy set from a byte slice.
func (dpi *defaultParserImplementationV1) ParsePolicySet(opts *options.ParseOptions, policySetData []byte) (*v1.PolicySet, attestation.Verification, error) {
	// Normalize HJSON to JSON if needed (must happen before envelope parsing)
	policySetData, err := normalizeToJSON(policySetData, opts.Limits.MaxJSONDepth)
	if err != nil {
		return nil, nil, fmt.Errorf("normalizing policy data: %w", err)
	}

	// Extract the policy predicate, if any
	policySetData, verification, err := parseEnvelope(opts, policySetData)
	if err != nil {
		return nil, nil, fmt.Errorf("testing for signature envelope: %w", err)
	}

	set := &v1.PolicySet{}
	err = protojson.UnmarshalOptions{
		AllowPartial:   false,
		DiscardUnknown: false,
	}.Unmarshal(policySetData, set)
	if err != nil {
		return nil, verification, fmt.Errorf("parsing policy set source: %w", err)
	}

	// Validate collection sizes
	if err := validatePolicySetLimits(opts, set); err != nil {
		return nil, verification, err
	}

	// Check the field constraints defined in the protobuf definitions
	if err := protovalidate.Validate(set); err != nil {
		return nil, verification, fmt.Errorf("validating policy set: %w", err)
	}

	// hash the data to record it in the policy origin
	hset, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(policySetData)})
	if err != nil {
		return nil, nil, fmt.Errorf("hashing policy data: %w", err)
	}

	if set.GetMeta() == nil {
		set.Meta = &v1.PolicySetMeta{}
	}

	if set.GetMeta().GetOrigin() == nil {
		set.GetMeta().Origin = &intoto.ResourceDescriptor{}
	}

	set.GetMeta().GetOrigin().Digest = hset.ToResourceDescriptors()[0].Digest
	set.GetMeta().GetOrigin().Name = set.GetId()

	if set.GetMeta().GetEnforce() == "" {
		set.GetMeta().Enforce = EnforceOn
	}

	for _, p := range set.Policies {
		// Don't apply defaults to policies with remote sources
		// They will get their defaults from the remote policy during assembly
		if p.GetSource() != nil {
			continue
		}

		if p.GetMeta() == nil {
			p.Meta = &v1.Meta{}
		}

		if p.GetMeta().GetAssertMode() == "" {
			p.GetMeta().AssertMode = AssertModeAND
		}

		if p.GetMeta().GetEnforce() == "" {
			p.GetMeta().Enforce = EnforceOn
		}
	}
	return set, verification, nil
}

// ParsePolicy parses a policy from a byte slice.
func (dpi *defaultParserImplementationV1) ParsePolicy(opts *options.ParseOptions, policyData []byte) (*v1.Policy, attestation.Verification, error) {
	// Normalize HJSON to JSON if needed (must happen before envelope parsing)
	policyData, err := normalizeToJSON(policyData, opts.Limits.MaxJSONDepth)
	if err != nil {
		return nil, nil, fmt.Errorf("normalizing policy data: %w", err)
	}

	// Extract the policy when used as a envelope's predicate
	policyData, verification, err := parseEnvelope(opts, policyData)
	if err != nil {
		return nil, nil, fmt.Errorf("testing for signature envelope: %w", err)
	}

	p := &v1.Policy{}
	err = protojson.UnmarshalOptions{}.Unmarshal(policyData, p)
	if err != nil {
		return nil, verification, fmt.Errorf("parsing policy source: %w", err)
	}

	// Validate collection sizes
	if err := validatePolicyLimits(opts, p); err != nil {
		return nil, verification, err
	}

	// Check the field constraints defined in the protobuf definitions
	if err := protovalidate.Validate(p); err != nil {
		return nil, verification, fmt.Errorf("validating policy: %w", err)
	}

	// hash the data to record it in the policy origin
	hset, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(policyData)})
	if err != nil {
		return nil, nil, fmt.Errorf("hashing policy data: %w", err)
	}

	if p.GetMeta() == nil {
		p.Meta = &v1.Meta{}
	}

	if p.GetMeta().GetOrigin() == nil {
		p.GetMeta().Origin = &intoto.ResourceDescriptor{}
	}

	p.GetMeta().GetOrigin().Digest = hset.ToResourceDescriptors()[0].Digest
	p.GetMeta().GetOrigin().Name = p.GetId()

	if p.GetMeta().GetEnforce() == "" {
		p.GetMeta().Enforce = EnforceOn
	}

	if p.GetMeta().GetAssertMode() == "" {
		p.GetMeta().AssertMode = AssertModeAND
	}

	return p, verification, nil
}

// ParsePolicyGroup parses a PolicyGroup from a byte slice.
func (dpi *defaultParserImplementationV1) ParsePolicyGroup(opts *options.ParseOptions, policyData []byte) (*v1.PolicyGroup, attestation.Verification, error) {
	// Normalize HJSON to JSON if needed (must happen before envelope parsing)
	policyData, err := normalizeToJSON(policyData, opts.Limits.MaxJSONDepth)
	if err != nil {
		return nil, nil, fmt.Errorf("normalizing policygroup data: %w", err)
	}

	// Extract the policy when used as a envelope's predicate
	policyGroupData, verification, err := parseEnvelope(opts, policyData)
	if err != nil {
		return nil, nil, fmt.Errorf("testing for signature envelope: %w", err)
	}

	g := &v1.PolicyGroup{}
	err = protojson.UnmarshalOptions{}.Unmarshal(policyGroupData, g)
	if err != nil {
		return nil, verification, fmt.Errorf("parsing group source: %w", err)
	}

	// Validate collection sizes
	if err := validatePolicyGroupLimits(opts, g); err != nil {
		return nil, verification, err
	}

	// Check the field constraints defined in the protobuf definitions
	if err := protovalidate.Validate(g); err != nil {
		return nil, verification, fmt.Errorf("validating policy group: %w", err)
	}

	// hash the data to record it in the policy origin
	hset, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(policyData)})
	if err != nil {
		return nil, nil, fmt.Errorf("hashing policy data: %w", err)
	}

	if g.GetMeta() == nil {
		g.Meta = &v1.PolicyGroupMeta{}
	}

	if g.GetMeta().GetOrigin() == nil {
		g.GetMeta().Origin = &intoto.ResourceDescriptor{}
	}

	g.GetMeta().GetOrigin().Digest = hset.ToResourceDescriptors()[0].Digest
	g.GetMeta().GetOrigin().Name = g.GetId()

	if g.GetMeta().GetEnforce() == "" {
		g.GetMeta().Enforce = EnforceOn
	}

	return g, verification, nil
}

// parseEnvelope parses a policy when wrapped in a cryptographic envelope.
func parseEnvelope(opts *options.ParseOptions, bundleData []byte) ([]byte, attestation.Verification, error) {
	p := envelope.Parsers
	envelopes, err := p.Parse(bytes.NewBuffer(bundleData))
	if err != nil {
		if errors.Is(err, attestation.ErrNotCorrectFormat) {
			return bundleData, nil, nil
		}
		return nil, nil, fmt.Errorf("parsing bundle: %w", err)
	}

	if len(envelopes) == 0 {
		return nil, nil, errors.New("no envelopes found in data")
	}

	// If no signature verification was requested, we can end here.
	if !opts.VerifySignatures {
		return envelopes[0].GetPredicate().GetData(), envelopes[0].GetPredicate().GetVerification(), nil
	}

	// Verify the signatures
	if err := envelopes[0].Verify(opts.PublicKeys); err != nil {
		return nil, nil, fmt.Errorf("verifying policy envelope: %w", err)
	}

	// If the envelope is not signed (verification is nil), then we can end here
	verification := envelopes[0].GetPredicate().GetVerification()
	if verification == nil {
		return envelopes[0].GetPredicate().GetData(), nil, nil
	}

	v, ok := verification.(*sapi.Verification)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported verification result type: %T", verification)
	}

	validIds := []*sapi.Identity{}
	for _, idstring := range opts.IdentityStrings {
		id, err := sapi.NewIdentityFromSpec(idstring)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing id string %q: %w", idstring, err)
		}
		validIds = append(validIds, id)
	}

	// If there were valid identities specified, we mutate the verification
	// results, in other words, white listing here and fail it if needed.
	if len(validIds) > 0 {
		acceptedIds := []*sapi.Identity{}
		for _, id := range validIds {
			if v.MatchesIdentity(id) {
				acceptedIds = append(acceptedIds, id)
			}
		}
		v.GetSignature().Identities = acceptedIds

		if len(acceptedIds) == 0 {
			v.GetSignature().Verified = false
			v.GetSignature().Error = fmt.Sprintf("unable to match signer with %d allowed identities", len(validIds))
		}
		verification = v
	}

	return envelopes[0].GetPredicate().GetData(), verification, nil
}
