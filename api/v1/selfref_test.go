// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestSelfReferencePath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		uri     string
		path    string
		mustErr bool
	}{
		{"file-at-root", "$/policy.hjson", "policy.hjson", false},
		{"file-in-directory", "$/slsa/slsa-builder-id.hjson", "slsa/slsa-builder-id.hjson", false},
		{"not-a-self-reference", "https://example.com/policy.json", "", true},
		{"vcs-locator", "git+https://example.com/repo#policy.json", "", true},
		{"dollar-without-slash", "$policy.json", "", true},
		{"no-path", "$/", "", true},
		{"dot", "$/.", "", true},
		{"rooted", "$//etc/passwd", "", true},
		{"parent-directory", "$/../policy.json", "", true},
		{"parent-directory-inside", "$/slsa/../../policy.json", "", true},
		{"current-directory", "$/./policy.json", "", true},
		{"empty-element", "$/slsa//policy.json", "", true},
		{"trailing-slash", "$/slsa/", "", true},
		{"revision", "$/slsa/policy.json@main", "", true},
		{"fragment", "$/slsa/policy.json#frag", "", true},
		{"query", "$/slsa/policy.json?x=1", "", true},
		{"backslash", `$/slsa\policy.json`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := SelfReferencePath(tc.uri)
			if tc.mustErr {
				require.Error(t, err)
				require.Empty(t, p)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.path, p)
			require.True(t, IsSelfReference(tc.uri))
		})
	}
}

// TestSelfReferencePinned checks that a well formed self reference counts as
// pinned with no digest, for both kinds of reference, and that a malformed
// one never does.
func TestSelfReferencePinned(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mustErr bool
		loc     *intoto.ResourceDescriptor
	}{
		{"no-digest", false, &intoto.ResourceDescriptor{Uri: "$/slsa/policy.hjson"}},
		{
			"with-digest", false,
			&intoto.ResourceDescriptor{Uri: "$/slsa/policy.hjson", Digest: map[string]string{"sha256": "2347962367823768"}},
		},
		{
			"unknown-digest-algorithm", true,
			&intoto.ResourceDescriptor{Uri: "$/slsa/policy.hjson", Digest: map[string]string{"sha2000-deluxe": "23479623"}},
		},
		{"escapes-repository", true, &intoto.ResourceDescriptor{Uri: "$/../policy.hjson"}},
		{
			"malformed-with-digest", true,
			&intoto.ResourceDescriptor{Uri: "$/../policy.hjson", Digest: map[string]string{"sha256": "2347962367823768"}},
		},
		{"in-download-location", true, &intoto.ResourceDescriptor{DownloadLocation: "$/slsa/policy.hjson"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, ref := range []RemoteReference{
				&PolicyRef{Location: tc.loc}, &PolicyGroupRef{Location: tc.loc},
			} {
				err := ref.Validate()
				if tc.mustErr {
					require.Error(t, err)
					continue
				}
				require.NoError(t, err)
			}
		})
	}
}

// TestValidateSelfReferenceSource checks that policies, groups and sets
// refuse a malformed self reference when validated, wherever it is written.
func TestValidateSelfReferenceSource(t *testing.T) {
	t.Parallel()
	good := &intoto.ResourceDescriptor{Uri: "$/slsa/policy.hjson"}
	bad := &intoto.ResourceDescriptor{Uri: "$/../../etc/passwd"}

	policyWith := func(loc *intoto.ResourceDescriptor) *Policy {
		return &Policy{Id: "p", Source: &PolicyRef{Location: loc}}
	}
	groupWith := func(src, policySrc *intoto.ResourceDescriptor) *PolicyGroup {
		return &PolicyGroup{
			Id:     "g",
			Source: &PolicyGroupRef{Location: src},
			Blocks: []*PolicyBlock{{Policies: []*Policy{policyWith(policySrc)}}},
		}
	}

	require.NoError(t, policyWith(good).Validate())
	require.Error(t, policyWith(bad).Validate())

	require.NoError(t, groupWith(good, good).Validate())
	require.Error(t, groupWith(bad, good).Validate())
	require.Error(t, groupWith(good, bad).Validate())

	require.NoError(t, (&PolicySet{
		Common:   &PolicySetCommon{References: []*PolicyRef{{Id: "r", Location: good}}},
		Policies: []*Policy{policyWith(good)},
		Groups:   []*PolicyGroup{groupWith(good, good)},
	}).Validate())
	require.Error(t, (&PolicySet{
		Common: &PolicySetCommon{References: []*PolicyRef{{Id: "r", Location: bad}}},
	}).Validate())
	require.Error(t, (&PolicySet{Policies: []*Policy{policyWith(bad)}}).Validate())
	require.Error(t, (&PolicySet{Groups: []*PolicyGroup{groupWith(good, bad)}}).Validate())

	// References of other kinds and policies without a source still pass.
	require.NoError(t, (&Policy{Id: "p"}).Validate())
	require.NoError(t, policyWith(&intoto.ResourceDescriptor{Uri: "https://example.com/p.json"}).Validate())
}
