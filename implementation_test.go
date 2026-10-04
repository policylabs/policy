// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/policylabs/policy/api/v1"
)

func TestNormalizeToJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       []byte
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, policy *api.Policy)
	}{
		{
			name: "ValidJSON",
			input: []byte(`{
				"id": "test-policy",
				"meta": {"description": "Test policy"}
			}`),
			validate: func(t *testing.T, policy *api.Policy) {
				assert.Equal(t, "test-policy", policy.Id)
			},
		},
		{
			name: "HJSONWithComments",
			input: []byte(`{
				# This is a test policy with comments
				id: "test-policy",
				meta: {
					description: "Test policy with HJSON comments",
					# Comments can appear anywhere
					assertMode: "AND"
				}
			}`),
			validate: func(t *testing.T, policy *api.Policy) {
				assert.Equal(t, "test-policy", policy.Id)
				assert.Equal(t, "Test policy with HJSON comments", policy.Meta.Description)
				assert.Equal(t, "AND", policy.Meta.AssertMode)
			},
		},
		{
			name: "HJSONWithTrailingCommas",
			input: []byte(`{
				id: "test-policy",
				meta: {
					description: "Test policy with trailing commas",
					enforce: "ON",
				},
				tenets: [
					{id: "tenet-1", code: "true",},
				],
			}`),
			validate: func(t *testing.T, policy *api.Policy) {
				assert.Equal(t, "test-policy", policy.Id)
				assert.Equal(t, "Test policy with trailing commas", policy.Meta.Description)
				assert.Len(t, policy.Tenets, 1)
			},
		},
		{
			name: "HJSONWithUnquotedKeys",
			input: []byte(`{
				id: "test-policy",
				meta: {
					description: "Test policy with unquoted keys",
					enforce: ON
				}
			}`),
			validate: func(t *testing.T, policy *api.Policy) {
				assert.Equal(t, "test-policy", policy.Id)
				assert.Equal(t, "Test policy with unquoted keys", policy.Meta.Description)
				assert.Equal(t, "ON", policy.Meta.Enforce)
			},
		},
		{
			name:        "InvalidData",
			input:       []byte(`{invalid json: [ unclosed bracket`),
			expectError: true,
			errorMsg:    "failed to parse as JSON or HJSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := normalizeToJSON(tt.input, 0) // 0 disables depth check for existing tests

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				parser := NewParser()
				policy, err := parser.ParsePolicy(result)
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, policy)
				}
			}
		})
	}
}

func TestParsePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		validate func(t *testing.T, policy *api.Policy)
	}{
		{
			name: "HJSON",
			input: []byte(`{
				# SLSA Build Level 3 Policy
				id: "slsa-build-3",
				meta: {
					description: "Verifies SLSA Build Level 3 compliance",
					enforce: "ON",
					assertMode: "AND",
				},
				identities: [{
					sigstore: {
						issuer: "https://token.actions.githubusercontent.com",
						identity: "https://github.com/test/repo/.github/workflows/release.yaml@refs/tags/v1.0",
					},
				}],
				tenets: [{
					id: "verify-builder",
					code: "true",
				}],
			}`),
			validate: func(t *testing.T, policy *api.Policy) {
				assert.Equal(t, "slsa-build-3", policy.Id)
				assert.Equal(t, "Verifies SLSA Build Level 3 compliance", policy.Meta.Description)
				assert.Equal(t, "ON", policy.Meta.Enforce)
				assert.Equal(t, "AND", policy.Meta.AssertMode)
				assert.Len(t, policy.Identities, 1)
				assert.Len(t, policy.Tenets, 1)
				assert.Equal(t, "verify-builder", policy.Tenets[0].Id)
			},
		},
		{
			name: "BackwardCompatibility",
			input: []byte(`{
				"id": "test-policy",
				"meta": {
					"description": "Standard JSON policy",
					"enforce": "ON",
					"assertMode": "AND"
				},
				"tenets": [{
					"id": "test-tenet",
					"code": "true"
				}]
			}`),
			validate: func(t *testing.T, policy *api.Policy) {
				assert.Equal(t, "test-policy", policy.Id)
				assert.Equal(t, "Standard JSON policy", policy.Meta.Description)
				assert.Equal(t, "ON", policy.Meta.Enforce)
				assert.Equal(t, "AND", policy.Meta.AssertMode)
				assert.Len(t, policy.Tenets, 1)
			},
		},
		{
			name: "HJSONMultilineStrings",
			input: []byte(`{
				id: "test-policy",
				meta: {
					description: '''
					This is a multi-line description
					that spans multiple lines
					and preserves formatting
					''',
				},
				tenets: [{
					id: "complex-tenet",
					code: '''
					has(predicates[0].data.buildDefinition) ?
					  (has(predicates[0].data.buildDefinition.resolvedDependencies) ?
					    (predicates[0].data.buildDefinition.resolvedDependencies.size() > 0) :
					    false) :
					  false
					''',
				}],
			}`),
			validate: func(t *testing.T, policy *api.Policy) {
				assert.Equal(t, "test-policy", policy.Id)
				assert.Contains(t, policy.Meta.Description, "multi-line")
				assert.Len(t, policy.Tenets, 1)
				assert.Contains(t, policy.Tenets[0].Code, "predicates[0].data.buildDefinition")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parser := NewParser()
			policy, err := parser.ParsePolicy(tt.input)
			require.NoError(t, err)
			require.NotNil(t, policy)
			if tt.validate != nil {
				tt.validate(t, policy)
			}
		})
	}
}

func TestParsePolicyValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		mustErr bool
	}{
		{
			name: "single-line-name",
			input: []byte(`{
				"id": "test-policy",
				"meta": {"name": "My Policy"},
				"tenets": [{"id": "test-tenet", "code": "true"}]
			}`),
			mustErr: false,
		},
		{
			name: "multiline-name",
			input: []byte(`{
				"id": "test-policy",
				"meta": {"name": "My\nPolicy"},
				"tenets": [{"id": "test-tenet", "code": "true"}]
			}`),
			mustErr: true,
		},
		{
			name: "invalid-transformer-id",
			input: []byte(`{
				"id": "test-policy",
				"transformers": [{"id": "external:Nope"}],
				"tenets": [{"id": "test-tenet", "code": "true"}]
			}`),
			mustErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policy, err := NewParser().ParsePolicy(tt.input)
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, policy)
		})
	}
}

func TestParsePolicySet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		validate func(t *testing.T, policySet *api.PolicySet)
	}{
		{
			name: "HJSON",
			input: []byte(`{
				# Policy Set for SLSA verification
				id: "slsa-verification-set",
				meta: {
					description: "Complete SLSA verification policy set",
					enforce: "ON",
				},
				common: {
					identities: [{
						id: "github-actions",
						sigstore: {
							issuer: "https://token.actions.githubusercontent.com",
							identity: "https://github.com/.*/.github/workflows/.*",
							mode: "regexp",
						},
					}],
				},
				policies: [{
					id: "slsa-builder-id",
					meta: {description: "Verify builder identity"},
					tenets: [{id: "check-builder", code: "true"}],
				}],
			}`),
			validate: func(t *testing.T, policySet *api.PolicySet) {
				assert.Equal(t, "slsa-verification-set", policySet.Id)
				assert.Equal(t, "Complete SLSA verification policy set", policySet.Meta.Description)
				assert.Equal(t, "ON", policySet.Meta.Enforce)
				assert.Len(t, policySet.Common.Identities, 1)
				assert.Equal(t, "github-actions", policySet.Common.Identities[0].Id)
				assert.Len(t, policySet.Policies, 1)
				assert.Equal(t, "slsa-builder-id", policySet.Policies[0].Id)
			},
		},
		{
			name: "BackwardCompatibility",
			input: []byte(`{
				"id": "test-set",
				"meta": {
					"description": "Standard JSON policy set",
					"enforce": "ON"
				},
				"policies": [{
					"id": "policy-1",
					"meta": {"description": "First policy"},
					"tenets": [{"id": "tenet-1", "code": "true"}]
				}]
			}`),
			validate: func(t *testing.T, policySet *api.PolicySet) {
				assert.Equal(t, "test-set", policySet.Id)
				assert.Equal(t, "Standard JSON policy set", policySet.Meta.Description)
				assert.Len(t, policySet.Policies, 1)
				assert.Equal(t, "policy-1", policySet.Policies[0].Id)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			parser := NewParser()
			policySet, err := parser.ParsePolicySet(tt.input)
			require.NoError(t, err)
			require.NotNil(t, policySet)
			if tt.validate != nil {
				tt.validate(t, policySet)
			}
		})
	}
}

// TestParsePolicyOrSet_HJSON tests the combined parser with HJSON input
func TestParsePolicyOrSet_HJSON(t *testing.T) {
	t.Parallel()

	hjsonPolicy := []byte(`{
		# Test policy in HJSON format
		id: "test-policy",
		meta: {
			description: "Test for ParsePolicyOrSet",
		},
		tenets: [
			{
				id: "test-tenet",
				code: "true"
			}
		]
	}`)

	parser := NewParser()
	policySet, policy, err := parser.ParsePolicyOrSet(hjsonPolicy)
	require.NoError(t, err)

	// Either Policy or PolicySet can be returned, but not both
	assert.True(t, (policySet != nil && policy == nil) || (policySet == nil && policy != nil))

	// Check that we got the right data
	if policy != nil {
		assert.Equal(t, "test-policy", policy.Id)
	} else {
		assert.Equal(t, "test-policy", policySet.Id)
	}
}
