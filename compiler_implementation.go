// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"
	"slices"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	api "github.com/policylabs/policy/api/v1"
)

type compilerImplementation interface {
	ValidateSet(*CompilerOptions, *api.PolicySet) error
	ValidatePolicy(*CompilerOptions, *api.Policy) error
	ExtractRemoteSetReferences(*CompilerOptions, *api.PolicySet) ([]api.RemoteReference, error)
	ExtractRemotePolicyReferences(*CompilerOptions, *api.Policy) ([]api.RemoteReference, error)
	FetchRemoteResources(*CompilerOptions, StorageBackend, []api.RemoteReference) error
	ValidateRemotes(*CompilerOptions, StorageBackend) error
	AssemblePolicySet(*CompilerOptions, *api.PolicySet, StorageBackend) error
	AssemblePolicy(*CompilerOptions, *api.Policy, StorageBackend) (*api.Policy, error)
	ValidateAssembledSet(*CompilerOptions, *api.PolicySet) error
	ValidateAssembledPolicy(*CompilerOptions, *api.Policy) error

	ValidatePolicyGroup(*CompilerOptions, *api.PolicyGroup) error
	ExtractRemotePolicyGroupReferences(*CompilerOptions, *api.PolicyGroup) ([]api.RemoteReference, error)
	AssemblePolicyGroup(*CompilerOptions, *api.PolicyGroup, StorageBackend) (*api.PolicyGroup, error)
	ValidateAssembledPolicyGroup(*CompilerOptions, *api.PolicyGroup) error
}

var _ compilerImplementation = &defaultCompilerImpl{}

type defaultCompilerImpl struct{}

func (dci *defaultCompilerImpl) ValidatePolicy(_ *CompilerOptions, p *api.Policy) error {
	return p.Validate()
}

func (dci *defaultCompilerImpl) ValidatePolicyGroup(_ *CompilerOptions, grp *api.PolicyGroup) error {
	return grp.Validate()
}

func (dci *defaultCompilerImpl) ValidateSet(_ *CompilerOptions, set *api.PolicySet) error {
	return set.Validate()
}

// ValidateAssembledPolicyGroup checks the integrity of a policy group
func (dci *defaultCompilerImpl) ValidateAssembledPolicyGroup(_ *CompilerOptions, grp *api.PolicyGroup) error {
	return grp.Validate()
}

// ExtractRemoteSetReferences extracts and enriches the remote references from all
// information available in (possibly) repeatead remote references.
func (dci *defaultCompilerImpl) ExtractRemoteSetReferences(opts *CompilerOptions, set *api.PolicySet) ([]api.RemoteReference, error) {
	// Add all the references we have, first the set-level refs:
	refs := []api.RemoteReference{}
	if set.GetCommon() != nil && set.GetCommon().GetReferences() != nil {
		for _, r := range set.GetCommon().GetReferences() {
			refs = append(refs, r)
		}
	}

	// .. remote group references
	for _, g := range set.GetGroups() {
		if g.GetSource() != nil {
			refs = append(refs, g.GetSource())
		}

		groupRefs, err := dci.ExtractRemotePolicyGroupReferences(opts, g)
		if err != nil {
			return nil, fmt.Errorf("fetching remote group refs: %w", err)
		}
		refs = append(refs, groupRefs...)
	}

	// ... and all policy sources
	for _, p := range set.GetPolicies() {
		if p.GetSource() != nil {
			refs = append(refs, p.GetSource())
		}
	}

	ret, err := dci.groupRemoteRefs(refs)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// ExtractRemotePolicyReferences extracts and enriches the remote references from all
// information available in (possibly) repeatead remote references.
func (dci *defaultCompilerImpl) ExtractRemotePolicyReferences(_ *CompilerOptions, p *api.Policy) ([]api.RemoteReference, error) {
	// Add all the references we have, first the set-level refs:
	refs := []api.RemoteReference{}
	if p.GetSource() != nil {
		refs = append(refs, p.GetSource())
	}

	ret, err := dci.groupRemoteRefs(refs)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

// ExtractRemoteSetReferences extracts and enriches the remote references from all
// information available in (possibly) repeatead remote references.
func (dci *defaultCompilerImpl) ExtractRemotePolicyGroupReferences(_ *CompilerOptions, grp *api.PolicyGroup) ([]api.RemoteReference, error) {
	refs := []api.RemoteReference{}
	// Get all the remote references from the policies
	for i := range grp.GetBlocks() {
		for _, p := range grp.GetBlocks()[i].GetPolicies() {
			if p.GetSource() != nil {
				refs = append(refs, p.GetSource())
			}
		}
	}

	ret, err := dci.groupRemoteRefs(refs)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (dci *defaultCompilerImpl) groupRemoteRefs(refs []api.RemoteReference) ([]api.RemoteReference, error) {
	uriIndex := map[string]api.RemoteReference{}
	ret := []api.RemoteReference{}

	// Rage over all refs and extract the ones that point to remote resources
	for _, ref := range refs {
		// If it does not have location coordinates, skip it
		if ref.GetLocation() == nil {
			continue
		}

		// Check if the policy has a DownloadLocation
		if ref.GetSourceURL() == "" {
			continue
		}

		url := ref.GetSourceURL()
		if _, ok := uriIndex[url]; !ok {
			uriIndex[url] = ref
			continue
		}

		if uriIndex[url].GetVersion() != ref.GetVersion() && uriIndex[url].GetVersion() != 0 && ref.GetVersion() != 0 {
			return nil, fmt.Errorf("inconsistency detected: version clash in remote refs")
		}

		if uriIndex[url].GetVersion() == 0 {
			uriIndex[url].SetVersion(ref.GetVersion())
		}

		for algo, val := range ref.GetLocation().GetDigest() {
			if v, ok := uriIndex[url].GetLocation().GetDigest()[algo]; ok {
				if v != val {
					return nil, fmt.Errorf("inconsistency detected, hash values clash for URI %s", url)
				}
			}
			uriIndex[url].GetLocation().Digest[algo] = val
		}
	}

	// Assemble the slice and return
	for _, ref := range uriIndex {
		ret = append(ret, ref)
	}
	return ret, nil
}

// fetchRemoteResources gets a list of remote references and fetches and caches
// the referenced elements. The fetchCount pointer tracks total fetches across
// recursive calls to enforce the MaxTotalFetches limit.
func (dci *defaultCompilerImpl) fetchRemoteResources(
	opts *CompilerOptions, recurse int, store StorageBackend, refs []api.RemoteReference, fetchCount *int,
) error {
	// Extract the URIs
	uris := []string{}
	newRefs := []api.RemoteReference{}
	for _, ref := range refs {
		haveIt := false
		switch cref := ref.(type) {
		case *api.PolicyRef:
			p, err := store.GetReferencedPolicy(ref)
			if err != nil {
				return fmt.Errorf("checking cached copy of referenced policy: %w", err)
			}
			if p != nil {
				haveIt = true
			}
		case *api.PolicyGroupRef:
			p, err := store.GetReferencedGroup(ref)
			if err != nil {
				return fmt.Errorf("checking cached copy of referenced policy: %w", err)
			}
			if p != nil {
				haveIt = true
			}
		default:
			return fmt.Errorf("unable to handle remote reference type %T", cref)
		}

		// If we already have a copy, skip
		if haveIt {
			continue
		}

		// Check if the policy has a DownloadLocation
		uri := ref.GetLocation().GetDownloadLocation()
		if uri == "" {
			uri = ref.GetLocation().GetUri()
		}
		uris = append(uris, uri)
		newRefs = append(newRefs, ref)
	}

	if len(uris) == 0 {
		logrus.Debugf("No remote resources required to fetch (from %d refs)", len(refs))
		return nil
	}

	// Check total fetch limit before fetching
	if opts.MaxTotalFetches > 0 && *fetchCount+len(uris) > opts.MaxTotalFetches {
		return fmt.Errorf("total fetches limit exceeded: limit=%d, would need=%d",
			opts.MaxTotalFetches, *fetchCount+len(uris))
	}

	logrus.Debugf("Fetching remote references (depth %d, total fetches: %d): %+v", recurse, *fetchCount, uris)

	// Create fetcher with batching support
	fetcher := NewFetcher()

	// Retrieve the remote data using batched fetching to limit parallelism
	var data [][]byte
	var err error
	if opts.MaxParallelFetches > 0 && len(uris) > opts.MaxParallelFetches {
		data, err = fetcher.GetGroupBatched(uris, opts.MaxParallelFetches)
	} else {
		data, err = fetcher.GetGroup(uris)
	}
	if err != nil {
		return fmt.Errorf("fetching remote data: %w", err)
	}

	// Update fetch count
	*fetchCount += len(uris)

	remotePolicies := []*api.Policy{}
	remoteSets := []*api.PolicySet{}
	remoteGroups := []*api.PolicyGroup{}

	// Store the retrieved data in the resource descriptor
	for i, datum := range data {
		// Here we shoud validate any hashes we have
		newRefs[i].GetLocation().Content = datum

		// Store the reference
		set, pcy, grp, err := store.StoreReferenceWithReturn(newRefs[i])
		if err != nil {
			return fmt.Errorf("storing external ref #%d: %w", i, err)
		}
		if set != nil {
			remoteSets = append(remoteSets, set)
		}
		if pcy != nil {
			remotePolicies = append(remotePolicies, pcy)
		}
		if grp != nil {
			remoteGroups = append(remoteGroups, grp)
		}
	}

	// Recurse any remote references
	rrefs := []api.RemoteReference{}

	// .. from any sets
	for _, s := range remoteSets {
		remotes, err := dci.ExtractRemoteSetReferences(opts, s)
		if err != nil {
			return fmt.Errorf("reparsing remote sets at level %d", recurse)
		}
		rrefs = append(rrefs, remotes...)
	}

	// .. policy groups
	for _, grp := range remoteGroups {
		remotes, err := dci.ExtractRemotePolicyGroupReferences(opts, grp)
		if err != nil {
			return fmt.Errorf("reparsing remote group refs at level %d", recurse)
		}
		rrefs = append(rrefs, remotes...)
	}

	// .. and single policies
	for _, pcy := range remotePolicies {
		if pcy.GetSource() != nil {
			rref, err := dci.groupRemoteRefs([]api.RemoteReference{pcy.Source})
			if err != nil {
				return fmt.Errorf("grouping policy source at level %d", recurse)
			}
			rrefs = append(rrefs, rref...)
		}
	}

	// If there are no remote refs, we can return here
	if len(rrefs) == 0 {
		return nil
	}

	// ... or if not, recurse
	return dci.fetchRemoteResources(opts, recurse+1, store, rrefs, fetchCount)
}

// FetchRemoteResources pulls all the remote data in parallel and stores it
// in the configured StorageBackend.
func (dci *defaultCompilerImpl) FetchRemoteResources(opts *CompilerOptions, store StorageBackend, refs []api.RemoteReference) error {
	if store == nil {
		return errors.New("storage backend missing")
	}

	fetchCount := 0
	return dci.fetchRemoteResources(opts, 0, store, refs, &fetchCount)
}

func (dci *defaultCompilerImpl) ValidateRemotes(*CompilerOptions, StorageBackend) error {
	return nil
}

func (dci *defaultCompilerImpl) assemblePolicy(opts *CompilerOptions, recurse int, p *api.Policy, store StorageBackend) (*api.Policy, error) {
	// If the policy does not have a remote source,
	// then we have nothing to do
	if p.GetSource() == nil {
		return p, nil
	}

	if recurse > opts.MaxRemoteRecursion {
		return nil, fmt.Errorf("maximum policy resolution recursion reached: %d", opts.MaxRemoteRecursion)
	}

	remotePolicy, err := store.GetReferencedPolicy(p.Source)
	if err != nil {
		return nil, fmt.Errorf("getting referenced policy: %w", err)
	}

	if remotePolicy == nil {
		return nil, fmt.Errorf("unable to complete policy, reference not resolved %v", p.GetSource())
	}

	if remotePolicy.GetSource() != nil {
		remotePolicy, err = dci.assemblePolicy(opts, recurse+1, remotePolicy, store)
		if err != nil {
			return nil, err
		}
	}

	assembledPolicy, ok := proto.Clone(remotePolicy).(*api.Policy)
	if !ok {
		return nil, fmt.Errorf("unable to cast reassembled policy: %w", err)
	}

	// index the tenet overlays:
	patches := map[string]*api.Tenet{}
	appenders := []*api.Tenet{}
	for _, t := range p.Tenets {
		// Tenets without ID (or, later, with IDs not matching the source policy)
		// will be added as new tenets to the policy. Only if IDs match on the
		// source and the overlay will be combined.
		if t.GetId() == "" {
			appenders = append(appenders, t)
			continue
		}
		patches[t.GetId()] = t
	}

	// Merge the local policy changes onto the remote:
	tenets := []*api.Tenet{}
	overlaysAdded := []string{}
	for _, t := range assembledPolicy.GetTenets() {
		nt, ok := proto.Clone(t).(*api.Tenet)
		if !ok {
			continue
		}
		if _, ok := patches[nt.GetId()]; nt.GetId() != "" && ok {
			proto.Merge(nt, patches[nt.GetId()])
		}
		overlaysAdded = append(overlaysAdded, nt.GetId())
		tenets = append(tenets, nt)
	}
	for id, t := range patches {
		if !slices.Contains(overlaysAdded, id) {
			tenets = append(tenets, t)
		}
	}
	tenets = append(tenets, appenders...)

	// Merge the policy overlay onto the remote policy
	// Only merge non-empty Meta fields to avoid overwriting with defaults
	if p.Meta != nil {
		if assembledPolicy.Meta == nil {
			assembledPolicy.Meta = &api.Meta{}
		}
		if p.Meta.Runtime != "" {
			assembledPolicy.Meta.Runtime = p.Meta.Runtime
		}
		if p.Meta.Name != "" {
			assembledPolicy.Meta.Name = p.Meta.Name
		}
		if p.Meta.Description != "" {
			assembledPolicy.Meta.Description = p.Meta.Description
		}
		if p.Meta.AssertMode != "" {
			assembledPolicy.Meta.AssertMode = p.Meta.AssertMode
		}
		if p.Meta.Version != 0 {
			assembledPolicy.Meta.Version = p.Meta.Version
		}
		if p.Meta.Enforce != "" {
			assembledPolicy.Meta.Enforce = p.Meta.Enforce
		}
		if p.Meta.Expiration != nil {
			assembledPolicy.Meta.Expiration = p.Meta.Expiration
		}
		if len(p.Meta.Controls) > 0 {
			assembledPolicy.Meta.Controls = p.Meta.Controls
		}
	}
	// Merge other fields (excluding Meta and Tenets which are handled separately)
	if p.Id != "" {
		assembledPolicy.Id = p.Id
	}
	if len(p.Context) > 0 {
		if assembledPolicy.Context == nil {
			assembledPolicy.Context = make(map[string]*api.ContextVal)
		}
		for k, v := range p.Context {
			assembledPolicy.Context[k] = v
		}
	}
	if len(p.Chain) > 0 {
		assembledPolicy.Chain = p.Chain
	}
	if len(p.Identities) > 0 {
		assembledPolicy.Identities = p.Identities
	}
	if p.Predicates != nil {
		assembledPolicy.Predicates = p.Predicates
	}
	if len(p.Transformers) > 0 {
		assembledPolicy.Transformers = p.Transformers
	}
	// A condition on the referencing stanza gates the referenced policy
	if p.When != nil {
		assembledPolicy.When = p.When
	}
	assembledPolicy.Tenets = tenets
	assembledPolicy.Source = nil
	return assembledPolicy, nil
}

// assemblePolicyGroup
func (dci *defaultCompilerImpl) assemblePolicyGroup(opts *CompilerOptions, grp *api.PolicyGroup, store StorageBackend) (*api.PolicyGroup, error) {
	// First, clone the PolicyGroup
	assembledGroup, ok := proto.Clone(grp).(*api.PolicyGroup)
	if !ok {
		return nil, fmt.Errorf("unable to cast reassembled group")
	}

	// // Fetch the data if the group is a remote reference
	if assembledGroup.GetSource() != nil {
		remotePolicyGroup, err := store.GetReferencedGroup(grp.GetSource())
		if err != nil {
			return nil, fmt.Errorf("getting referenced PolicyGroup: %w", err)
		}

		if remotePolicyGroup == nil {
			return nil, fmt.Errorf("unable to complete PolicyGroup, reference %v not resolved", grp.GetSource())
		}

		// Remote blocks are merged below: a remote block replaces the local
		// block sharing its id (keeping the local condition) and the rest are
		// appended, so ids never end up duplicated.
		if assembledGroup.GetMeta() == nil {
			assembledGroup.Meta = &api.PolicyGroupMeta{}
		}

		// Merge the meta fields
		if assembledGroup.GetMeta().GetName() == "" {
			assembledGroup.GetMeta().Name = remotePolicyGroup.GetMeta().GetName()
		}
		if assembledGroup.GetMeta().GetDescription() == "" {
			assembledGroup.GetMeta().Description = remotePolicyGroup.GetMeta().GetDescription()
		}

		// int64 version = 2; <<< Version is not inherited
		if len(assembledGroup.GetMeta().GetControls()) == 0 {
			assembledGroup.GetMeta().Controls = remotePolicyGroup.GetMeta().GetControls()
		}
		if assembledGroup.GetMeta().GetEnforce() == "" {
			assembledGroup.GetMeta().Enforce = remotePolicyGroup.GetMeta().GetEnforce()
		}
		if assembledGroup.GetMeta().GetAssertMode() == "" {
			assembledGroup.GetMeta().AssertMode = remotePolicyGroup.GetMeta().GetAssertMode()
		}
		// optional google.protobuf.Timestamp expiration = 5; <<< Expiration is not inherited
		// optional in_toto_attestation.v1.ResourceDescriptor origin = 6; <<< From pulled data

		// TODO(puerco): If remote policy group has a remote ref, then what? Fail?

		// Inherit the group ID from the remote group if local is empty
		if assembledGroup.GetId() == "" {
			assembledGroup.Id = remotePolicyGroup.GetId()
		}

		// Nil the group source to mimic how we handle it in remote policies.
		assembledGroup.Source = nil

		// Index the overlay blocks, we only merge remote blocks if:
		//   a) The overlay does not have one with the same ID
		//   b) or if the remote block does not have an ID
		blockIndex := map[string]int{}
		for i, b := range assembledGroup.GetBlocks() {
			if b.GetId() == "" {
				continue
			}
			blockIndex[b.GetId()] = i
		}

		// Now, merge the remote blocks
		for _, b := range remotePolicyGroup.GetBlocks() {
			// Case b: No ID in remote block
			if b.GetId() == "" {
				assembledGroup.Blocks = append(assembledGroup.Blocks, b)
				continue
			}

			i, ok := blockIndex[b.GetId()]
			if ok {
				// Case a1: Replace overlay when ID matches
				// A condition set on the local block gates the merged result
				localWhen := assembledGroup.Blocks[i].GetWhen()
				assembledGroup.Blocks[i] = b
				if localWhen != nil {
					assembledGroup.Blocks[i].When = localWhen
				}
				continue
			}

			// Case a2: Remote block has an ID but there's no local match
			assembledGroup.Blocks = append(assembledGroup.Blocks, b)
		}
	}

	// TODO(puerco): Check meta ?
	for i := range assembledGroup.GetBlocks() {
		for j := range assembledGroup.GetBlocks()[i].GetPolicies() {
			p, err := dci.assemblePolicy(opts, 0, assembledGroup.GetBlocks()[i].GetPolicies()[j], store)
			if err != nil {
				return nil, fmt.Errorf("assembling policy #%d of block #%d: %w", j, i, err)
			}
			assembledGroup.Blocks[i].Policies[j] = p
		}
	}
	return assembledGroup, nil
}

// AssemblePolicyGroup
func (dci *defaultCompilerImpl) AssemblePolicyGroup(opts *CompilerOptions, grp *api.PolicyGroup, store StorageBackend) (*api.PolicyGroup, error) {
	assembledGroup, err := dci.assemblePolicyGroup(opts, grp, store)
	if err != nil {
		return nil, fmt.Errorf("assembling policy group: %w", err)
	}
	return assembledGroup, nil
}

func (dci *defaultCompilerImpl) AssemblePolicySet(opts *CompilerOptions, set *api.PolicySet, store StorageBackend) error {
	for i, p := range set.Policies {
		assembledPolicy, err := dci.assemblePolicy(opts, 0, p, store)
		if err != nil {
			return fmt.Errorf("assembling policy #%d: %w", i, err)
		}
		// Now replace the local in the policy set with the enriched remote
		set.Policies[i] = assembledPolicy
	}

	// Assemble the PolicyGroups
	for i, grp := range set.Groups {
		assembledGroup, err := dci.assemblePolicyGroup(opts, grp, store)
		if err != nil {
			return fmt.Errorf("assembling group #%d: %w", i, err)
		}
		set.Groups[i] = assembledGroup
	}

	if set.GetCommon() == nil {
		set.Common = &api.PolicySetCommon{}
	} else {
		set.GetCommon().References = nil
	}
	return nil
}

// AssemblePolicy takes a policy and fetches all its pieces and returns the
// assembled version
func (dci *defaultCompilerImpl) AssemblePolicy(opts *CompilerOptions, p *api.Policy, store StorageBackend) (*api.Policy, error) {
	assembledPolicy, err := dci.assemblePolicy(opts, 0, p, store)
	if err != nil {
		return nil, fmt.Errorf("assembling policy: %w", err)
	}
	return assembledPolicy, nil
}

func (dci *defaultCompilerImpl) ValidateAssembledSet(*CompilerOptions, *api.PolicySet) error {
	return nil
}

func (dci *defaultCompilerImpl) ValidateAssembledPolicy(_ *CompilerOptions, p *api.Policy) error {
	return p.Validate()
}
