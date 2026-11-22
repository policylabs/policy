// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"testing"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"

	api "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
)

func TestParseLocalGroups(t *testing.T) {
	t.Parallel()
	t.Run("test-parse-localset-group", func(t *testing.T) {
		t.Parallel()
		set, err := NewParser().ParsePolicySetFile("testdata/groups-local.json")
		require.NoError(t, err)
		require.NotNil(t, set)

		require.Equal(t, "Simple policy set tp test locally defined policy groups", set.GetMeta().GetDescription())
		require.Empty(t, set.GetPolicies())
		require.Len(t, set.GetGroups(), 1)
		require.Len(t, set.GetGroups()[0].GetBlocks(), 4)
		require.Equal(t, "single-passing", set.GetGroups()[0].GetBlocks()[0].GetId())
		require.Len(t, set.GetGroups()[0].GetBlocks()[1].GetPolicies(), 2)
	})

	t.Run("test-parse-local-group", func(t *testing.T) {
		t.Parallel()
		grp, err := NewParser().ParsePolicyGroupFile("testdata/group.single.json")
		require.NoError(t, err)
		require.NotNil(t, grp)

		require.Equal(t, "Group testing the assert modes", grp.GetMeta().GetDescription())
		require.Len(t, grp.GetBlocks(), 4)
		require.Equal(t, "single-passing", grp.GetBlocks()[0].GetId())
		require.Len(t, grp.GetBlocks()[1].GetPolicies(), 2)
	})
}

func TestParseLocalPolicies(t *testing.T) {
	t.Parallel()
	t.Run("test-parse-localset-policy", func(t *testing.T) {
		t.Parallel()
		set, err := NewParser().ParsePolicySetFile("testdata/policies-local.json")
		require.NoError(t, err)
		require.NotNil(t, set)

		require.Equal(t, "Simple policy set to test locally defined policies", set.GetMeta().GetDescription())
		require.Len(t, set.GetPolicies(), 2)
		require.Empty(t, set.GetGroups())
		require.Equal(t, "local-policy-1", set.GetPolicies()[0].GetId())
		require.Equal(t, "AND", set.GetPolicies()[0].GetMeta().GetAssertMode())
		require.Len(t, set.GetPolicies()[0].GetTenets(), 2)
		require.Equal(t, "local-policy-2", set.GetPolicies()[1].GetId())
		require.Equal(t, "OR", set.GetPolicies()[1].GetMeta().GetAssertMode())
	})

	t.Run("test-parse-local-policy", func(t *testing.T) {
		t.Parallel()
		policy, err := NewParser().ParsePolicyFile("testdata/policy.single.json")
		require.NoError(t, err)
		require.NotNil(t, policy)

		require.Equal(t, "Policy testing the assert modes and tenets", policy.GetMeta().GetDescription())
		require.Equal(t, "policy-assert-mode-test", policy.GetId())
		require.Equal(t, "AND", policy.GetMeta().GetAssertMode())
		require.Len(t, policy.GetTenets(), 2)
		require.Equal(t, "tenet-1", policy.GetTenets()[0].GetId())
		require.Equal(t, "tenet-2", policy.GetTenets()[1].GetId())
	})
}

// TestParseRejectsMultilineNames checks the parser enforces single-line
// names on sets and groups, like it does on policies.
func TestParseRejectsMultilineNames(t *testing.T) {
	t.Parallel()
	parser := NewParser()

	set, err := parser.ParsePolicySet([]byte(`{"id": "s", "meta": {"name": "drop release"}, "policies": []}`))
	require.NoError(t, err)
	require.Equal(t, "drop release", set.GetMeta().GetName())
	_, err = parser.ParsePolicySet([]byte(`{"id": "s", "meta": {"name": "two\nlines"}, "policies": []}`))
	require.Error(t, err)

	grp, err := parser.ParsePolicyGroup([]byte(`{"id": "g", "meta": {"name": "OSPS baseline"}, "blocks": []}`))
	require.NoError(t, err)
	require.Equal(t, "OSPS baseline", grp.GetMeta().GetName())
	_, err = parser.ParsePolicyGroup([]byte(`{"id": "g", "meta": {"name": "two\nlines"}, "blocks": []}`))
	require.Error(t, err)
}

// kindVerification is a verification that says which parse it came from.
type kindVerification string

func (kindVerification) GetVerified() bool        { return true }
func (kindVerification) MatchesIdentity(any) bool { return false }

// kindParser parses data as the kinds it is told to, answering for each a
// verification of its own, also when the parse fails: the default
// implementation reads the envelope before it knows the kind.
type kindParser struct {
	set, policy, group bool
}

func (k *kindParser) ParsePolicySet(*options.ParseOptions, []byte) (*api.PolicySet, attestation.Verification, error) {
	if k.set {
		return &api.PolicySet{Id: "set"}, kindVerification("set"), nil
	}
	return nil, kindVerification("failed set"), errors.New(`unknown field "tenets"`)
}

func (k *kindParser) ParsePolicy(*options.ParseOptions, []byte) (*api.Policy, attestation.Verification, error) {
	if k.policy {
		return &api.Policy{Id: "policy"}, kindVerification("policy"), nil
	}
	return nil, kindVerification("failed policy"), errors.New(`unknown field "policies"`)
}

func (k *kindParser) ParsePolicyGroup(*options.ParseOptions, []byte) (*api.PolicyGroup, attestation.Verification, error) {
	if k.group {
		return &api.PolicyGroup{Id: "group"}, kindVerification("group"), nil
	}
	return nil, kindVerification("failed group"), errors.New(`unknown field "policies"`)
}

// The data is parsed as a policy, a set and a group at once, and each parse
// verifies the envelope for itself. The verification returned is the one of
// the kind the data is, every time: the three parses used to write it to the
// same variable, and the last to finish won. Run with -race, this is also
// where that showed.
func TestParseVerifyPolicyOrSetOrGroupVerification(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		parses kindParser
		want   attestation.Verification
	}{
		{name: "a set", parses: kindParser{set: true}, want: kindVerification("set")},
		{name: "a policy", parses: kindParser{policy: true}, want: kindVerification("policy")},
		{name: "a group", parses: kindParser{group: true}, want: kindVerification("group")},
		// Data that reads as more than one kind is taken as the kind
		// PolicyOrSetOrGroup picks, and verified as that one.
		{name: "a set first", parses: kindParser{set: true, policy: true, group: true}, want: kindVerification("set")},
		{name: "a policy before a group", parses: kindParser{policy: true, group: true}, want: kindVerification("policy")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &Parser{impl: &tc.parses}
			for range 200 {
				set, pcy, grp, v, err := p.ParseVerifyPolicyOrSetOrGroup([]byte(`{}`))
				require.NoError(t, err)
				require.Equal(t, tc.want, v)
				require.Equal(t, tc.parses.set, set != nil)
				require.Equal(t, tc.parses.policy, pcy != nil)
				require.Equal(t, tc.parses.group, grp != nil)
			}
		})
	}

	// Nothing parsed: there is an error and no verification, not that of a
	// parse that failed.
	t.Run("none", func(t *testing.T) {
		t.Parallel()
		p := &Parser{impl: &kindParser{}}
		for range 200 {
			set, pcy, grp, v, err := p.ParseVerifyPolicyOrSetOrGroup([]byte(`{}`))
			require.Error(t, err)
			require.Nil(t, v)
			require.Nil(t, set)
			require.Nil(t, pcy)
			require.Nil(t, grp)
		}
	})
}
