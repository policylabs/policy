// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"

	api "github.com/policylabs/policy/api/v1"
)

// referenceLocations returns the location of every reference written in a
// document, the one that is not nil, including those of the policies and
// groups nested in it. They are the descriptors of the document itself, so
// changing one changes the reference.
func referenceLocations(set *api.PolicySet, pcy *api.Policy, grp *api.PolicyGroup) []*intoto.ResourceDescriptor {
	locs := []*intoto.ResourceDescriptor{}
	add := func(ref api.RemoteReference) {
		if l := ref.GetLocation(); l != nil {
			locs = append(locs, l)
		}
	}
	addGroup := func(g *api.PolicyGroup) {
		add(g.GetSource())
		for _, b := range g.GetBlocks() {
			for _, p := range b.GetPolicies() {
				add(p.GetSource())
			}
		}
	}

	switch {
	case set != nil:
		for _, r := range set.GetCommon().GetReferences() {
			add(r)
		}
		for _, p := range set.GetPolicies() {
			add(p.GetSource())
		}
		for _, g := range set.GetGroups() {
			addGroup(g)
		}
	case pcy != nil:
		add(pcy.GetSource())
	case grp != nil:
		addGroup(grp)
	}
	return locs
}

// resolveSelfReferences resolves the self references ("$/" references, see
// api.SelfReferencePrefix) among the locations of the references of a
// document, against the location the document was read from. The location
// a reference resolves to is recorded as its download location, which is
// where the compiler fetches a reference from, and its uri is kept as
// written.
//
// The base is pinned before resolving against it, so that all the self
// references of a document are read at one revision. A document with self
// references fails with ErrSelfReferenceUnresolved when the base is empty,
// and with ErrSelfReferenceUnsupported when it is not in a repository.
func resolveSelfReferences(
	ctx context.Context, fetcher *Fetcher, base string, locs []*intoto.ResourceDescriptor,
) error {
	pinned := ""
	for _, loc := range locs {
		if !api.IsSelfReference(loc.GetUri()) {
			continue
		}
		path, err := api.SelfReferencePath(loc.GetUri())
		if err != nil {
			return err
		}
		if base == "" {
			return fmt.Errorf("%w: %q", ErrSelfReferenceUnresolved, loc.GetUri())
		}
		if pinned == "" {
			if pinned, err = fetcher.PinLocation(ctx, base); err != nil {
				return fmt.Errorf("pinning the location of the document: %w", err)
			}
		}

		// Whatever the document wrote as the download location of a self
		// reference is replaced, it never chooses where one is read from.
		resolved, err := fetcher.ResolveSelf(pinned, path)
		if err != nil {
			return fmt.Errorf("resolving %q: %w", loc.GetUri(), err)
		}
		loc.DownloadLocation = resolved
	}
	return nil
}
