// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"
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
