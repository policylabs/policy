// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sirupsen/logrus"

	api "github.com/policylabs/policy/api/v1"
)

// Storage backend is an interface that fronts systems that store and index policies
type StorageBackend interface {
	StoreReference(api.RemoteReference) error
	StoreReferenceWithReturn(api.RemoteReference) (*api.PolicySet, *api.Policy, *api.PolicyGroup, error)
	GetReferencedPolicy(api.RemoteReference) (*api.Policy, error)
	GetReferencedGroup(api.RemoteReference) (*api.PolicyGroup, error)
}

func newRefStore() *refStore {
	return &refStore{
		references:   map[string]api.RemoteReference{},
		policySets:   map[string]*api.PolicySet{},
		policies:     map[string]*api.Policy{},
		policyGroups: map[string]*api.PolicyGroup{},
		ids:          map[string]string{},
		urls:         map[string]string{},
		hashes:       map[string]string{},
	}
}

var _ StorageBackend = &refStore{}

type refStore struct {
	references   map[string]api.RemoteReference
	policySets   map[string]*api.PolicySet
	policies     map[string]*api.Policy
	policyGroups map[string]*api.PolicyGroup
	ids          map[string]string
	urls         map[string]string
	hashes       map[string]string
}

// StoreReference stores a reference and adds it to the index
func (rs *refStore) StoreReference(ref api.RemoteReference) error {
	_, _, _, err := rs.StoreReferenceWithReturn(ref)
	return err
}

// StoreReferenceWithReturn stores a policy reference returning the parsed
// Policy or PolicySet from the ref content.
func (rs *refStore) StoreReferenceWithReturn(ref api.RemoteReference) (*api.PolicySet, *api.Policy, *api.PolicyGroup, error) {
	if ref.GetLocation() == nil {
		return nil, nil, nil, fmt.Errorf("unable to store policy no location data found")
	}

	// If the policy content is nil at some point we could try to fetch it
	// but for now we use the fetcher as it it can fet in parallel.
	if ref.GetLocation().GetContent() == nil {
		return nil, nil, nil, fmt.Errorf("unable to store policy, content is empty")
	}

	if ref.GetLocation().GetDigest() == nil {
		ref.GetLocation().Digest = map[string]string{}
	}

	// Hash the policy contents, this will be the main storage key
	h := sha256.New()
	h.Write(ref.GetLocation().GetContent())

	contentHash := fmt.Sprintf("%x", h.Sum(nil))

	// If the ref is missing its sha256 digest, generate it
	if _, ok := ref.GetLocation().GetDigest()[string(intoto.AlgorithmSHA256)]; !ok {
		ref.GetLocation().GetDigest()[string(intoto.AlgorithmSHA256)] = contentHash
	} else if contentHash != ref.GetLocation().GetDigest()[string(intoto.AlgorithmSHA256)] {
		return nil, nil, nil, fmt.Errorf("policy sha256 digest does not match content")
	}

	// TODO(puerco) Here the reference should be augmented if it already exists
	rs.references[contentHash] = ref

	uri := ref.GetLocation().GetDownloadLocation()
	if uri == "" {
		uri = ref.GetLocation().GetUri()
	}
	if uri != "" {
		rs.urls[uri] = contentHash
	}

	for algo, val := range ref.GetLocation().GetDigest() {
		rs.hashes[fmt.Sprintf("%s:%s", algo, val)] = contentHash
	}

	// Parse the data and assign whatever comes out of it
	set, pcy, grp, _, err := NewParser().ParseVerifyPolicyOrSetOrGroup(ref.GetLocation().GetContent())

	// Here, we record the policy source url in the origin. It's not great
	// to be doing it here but otherwise the cached data will not have it.
	sourceURI := ref.GetLocation().GetDownloadLocation()
	if sourceURI == "" {
		sourceURI = ref.GetLocation().GetUri()
	}

	switch {
	case set != nil:
		if err := rs.registerPolicySet(contentHash, set); err != nil {
			return nil, nil, nil, fmt.Errorf("indexing policy set: %w", err)
		}
		set.GetMeta().GetOrigin().DownloadLocation = sourceURI
		if set.GetMeta().GetOrigin().Uri == "" {
			set.GetMeta().GetOrigin().Uri = sourceURI
		}
	case pcy != nil:
		if err := rs.registerPolicy(contentHash, pcy); err != nil {
			return nil, nil, nil, fmt.Errorf("indexing policy: %w", err)
		}
		pcy.GetMeta().GetOrigin().DownloadLocation = sourceURI
		if pcy.GetMeta().GetOrigin().Uri == "" {
			pcy.GetMeta().GetOrigin().Uri = sourceURI
		}
	case grp != nil:
		if err := rs.registerGroup(contentHash, grp); err != nil {
			return nil, nil, nil, fmt.Errorf("indexing group: %w", err)
		}
		grp.GetMeta().GetOrigin().DownloadLocation = sourceURI
		if grp.GetMeta().GetOrigin().Uri == "" {
			grp.GetMeta().GetOrigin().Uri = sourceURI
		}
	case err != nil:
		return nil, nil, nil, err
	}
	return set, pcy, grp, err
}

// registerPolicy register a policy, not form a set.
func (rs *refStore) registerPolicy(contentHash string, pcy *api.Policy) error {
	if pcy.GetId() != "" {
		if currentHash, ok := rs.ids[pcy.GetId()]; ok {
			if currentHash != contentHash {
				return fmt.Errorf("duplicate policy ID %q with different hash", pcy.GetId())
			}
		}
	}
	rs.ids[pcy.GetId()] = contentHash
	rs.policies[contentHash] = pcy
	return nil
}

// registerPolicy register a policy, not form a set.
func (rs *refStore) registerGroup(contentHash string, grp *api.PolicyGroup) error {
	if grp.GetId() != "" {
		if currentHash, ok := rs.ids[grp.GetId()]; ok {
			if currentHash != contentHash {
				return fmt.Errorf("duplicate policy group ID %q with different hash", grp.GetId())
			}
		}
	}
	rs.ids[grp.GetId()] = contentHash
	rs.policyGroups[contentHash] = grp
	return nil
}

// registerPolicySet registers the policy in the storage index
func (rs *refStore) registerPolicySet(contentHash string, set *api.PolicySet) error {
	if set == nil {
		return errors.New("attempt to index null policy set")
	}
	rs.policySets[contentHash] = set

	// Store all the policy IDs in the referenced set
	for _, p := range set.GetPolicies() {
		// If a policy does not have an id, it cannot be referenced in a
		// set, so we skip indexing it.
		if p.GetId() == "" {
			continue
		}

		// Check we don't already have the policy ID in another file
		if currentHash, ok := rs.ids[p.GetId()]; ok {
			if currentHash != contentHash {
				return fmt.Errorf("duplicate policy id %q with different hash", p.GetId())
			}
		}
		rs.ids[p.GetId()] = contentHash
	}
	return nil
}

// This retrieves a policy from the sets by its source URL
func (rs *refStore) GetPolicyByURL(url string) *api.Policy {
	sha, ok := rs.urls[url]
	if !ok {
		return nil
	}
	return rs.GetPolicyBySHA256(sha)
}

// This retrieves a policy from the sets by its source URL
func (rs *refStore) GetPolicyGroupByURL(url string) *api.PolicyGroup {
	sha, ok := rs.urls[url]
	if !ok {
		return nil
	}
	return rs.GetPolicyGroupBySHA256(sha)
}

// This retrieves a policy from the sets by its ID
func (rs *refStore) GetPolicyByID(id string) *api.Policy {
	sha, ok := rs.ids[id]
	if !ok || id == "" {
		return nil
	}

	if _, ok := rs.policies[sha]; ok {
		return rs.policies[sha]
	}

	if _, ok := rs.policyGroups[sha]; ok {
		return nil
	}

	if _, ok := rs.policySets[sha]; !ok {
		return nil
	}

	for _, p := range rs.policySets[sha].GetPolicies() {
		if p.GetId() == id {
			return p
		}
	}

	// This should never happen as it would point to a corrupt index
	logrus.Warnf("Indexed policy-id %q points to PolicySet that does not have it", id)
	return nil
}

// This retrieves a policy from the sets by its ID
func (rs *refStore) GetPolicyGroupByID(id string) *api.PolicyGroup {
	sha, ok := rs.ids[id]
	if !ok || id == "" {
		return nil
	}

	if _, ok := rs.policyGroups[sha]; ok {
		return rs.policyGroups[sha]
	}

	if _, ok := rs.policies[sha]; ok {
		return nil
	}

	if _, ok := rs.policySets[sha]; !ok {
		return nil
	}

	for _, p := range rs.policySets[sha].GetGroups() {
		if p.GetId() == id {
			return p
		}
	}

	// This should never happen as it would point to a corrupt index
	logrus.Warnf("Indexed PolicyGroup id %q points to PolicySet that does not have it", id)
	return nil
}

func (rs *refStore) GetPolicyBySHA256(sha string) *api.Policy {
	if _, ok := rs.policies[sha]; ok {
		return rs.policies[sha]
	}

	if _, ok := rs.policySets[sha]; !ok {
		return nil
	}

	return nil
}

func (rs *refStore) GetPolicySetBySHA256(sha string) *api.PolicySet {
	sha = strings.TrimPrefix(sha, "sha256:")
	if v, ok := rs.policySets[sha]; ok {
		return v
	}
	return nil
}

func (rs *refStore) GetPolicyGroupBySHA256(sha string) *api.PolicyGroup {
	sha = strings.TrimPrefix(sha, "sha256:")
	if v, ok := rs.policyGroups[sha]; ok {
		return v
	}
	return nil
}

func (rs *refStore) GetRemoteRefBySHA256(sha string) api.RemoteReference {
	if v, ok := rs.references[sha]; ok {
		return v
	}
	return nil
}

// GetReferencedPolicy
func (rs *refStore) GetReferencedPolicy(ref api.RemoteReference) (*api.Policy, error) {
	// Try finding the policy by indexed ID
	if p := rs.GetPolicyByID(ref.GetId()); p != nil {
		return p, nil
	}

	if p := rs.GetPolicyByURL(ref.GetSourceURL()); p != nil {
		return p, nil
	}

	// Can't locate it through any other means
	return nil, nil
}

// GetReferencedPolicy
func (rs *refStore) GetReferencedGroup(ref api.RemoteReference) (*api.PolicyGroup, error) {
	// Try finding the policy by indexed ID
	if p := rs.GetPolicyGroupByID(ref.GetId()); p != nil {
		return p, nil
	}

	if p := rs.GetPolicyGroupByURL(ref.GetSourceURL()); p != nil {
		return p, nil
	}

	// Can't locate it through any other means
	return nil, nil
}

// This error is thrown if a fetchedRef lists a policy ID not
// contained in its policy or policy set. If it's ever thrown
// it is definitely a bug:
var ErrParseInconsistency = errors.New("internal error: fetched reference ID and policy ID mismatch")
