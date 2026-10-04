// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/policylabs/policy/api/v1"
)

func TestExtractRemotePolicyGroupReferences(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		group       *api.PolicyGroup
		expectError bool
		errorMsg    string
		validate    func(t *testing.T, refs []api.RemoteReference)
	}{
		{
			name: "EmptyPolicyGroup",
			group: &api.PolicyGroup{
				Id:     "empty-group",
				Blocks: []*api.PolicyBlock{},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				assert.Empty(t, refs)
			},
		},
		{
			name: "NoRemoteReferences",
			group: &api.PolicyGroup{
				Id: "local-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Meta: &api.Meta{
									Description: "Local policy",
								},
								// No source - this is a local policy
							},
							{
								Id: "policy-2",
								Meta: &api.Meta{
									Description: "Another local policy",
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				assert.Empty(t, refs)
			},
		},
		{
			name: "SingleRemoteReference",
			group: &api.PolicyGroup{
				Id: "group-with-remote",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy-1",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy1.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				require.Len(t, refs, 1)
				assert.Equal(t, "remote-policy-1", refs[0].GetId())
				assert.Equal(t, int64(1), refs[0].GetVersion())
				assert.Equal(t, "https://example.com/policy1.json", refs[0].GetSourceURL())
			},
		},
		{
			name: "MultipleBlocksWithReferences",
			group: &api.PolicyGroup{
				Id: "multi-block-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy-1",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy1.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
						},
					},
					{
						Id: "block-2",
						Policies: []*api.Policy{
							{
								Id: "policy-2",
								Source: &api.PolicyRef{
									Id:      "remote-policy-2",
									Version: 2,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy2.json",
										Digest: map[string]string{
											"sha256": "def456",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				require.Len(t, refs, 2)
				// References might be in any order
				urls := make(map[string]bool)
				for _, ref := range refs {
					urls[ref.GetSourceURL()] = true
				}
				assert.True(t, urls["https://example.com/policy1.json"])
				assert.True(t, urls["https://example.com/policy2.json"])
			},
		},
		{
			name: "MixedLocalAndRemotePolicies",
			group: &api.PolicyGroup{
				Id: "mixed-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "local-policy",
								Meta: &api.Meta{
									Description: "Local policy without source",
								},
							},
							{
								Id: "remote-policy",
								Source: &api.PolicyRef{
									Id:      "remote-ref",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/remote.json",
										Digest: map[string]string{
											"sha256": "xyz789",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				require.Len(t, refs, 1)
				assert.Equal(t, "https://example.com/remote.json", refs[0].GetSourceURL())
			},
		},
		{
			name: "DuplicateReferences_SameVersion",
			group: &api.PolicyGroup{
				Id: "duplicate-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
							{
								Id: "policy-2",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				// Should be deduplicated to a single reference
				require.Len(t, refs, 1)
				assert.Equal(t, "https://example.com/policy.json", refs[0].GetSourceURL())
				assert.Equal(t, int64(1), refs[0].GetVersion())
			},
		},
		{
			name: "DuplicateReferences_VersionMerge",
			group: &api.PolicyGroup{
				Id: "version-merge-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 0, // No version specified
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
							{
								Id: "policy-2",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1, // Version specified
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				require.Len(t, refs, 1)
				// Version should be merged to the non-zero version
				assert.Equal(t, int64(1), refs[0].GetVersion())
			},
		},
		{
			name: "DuplicateReferences_VersionConflict",
			group: &api.PolicyGroup{
				Id: "version-conflict-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
							{
								Id: "policy-2",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 2, // Different version
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "version clash",
		},
		{
			name: "DuplicateReferences_HashConflict",
			group: &api.PolicyGroup{
				Id: "hash-conflict-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
							{
								Id: "policy-2",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "def456", // Different hash
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "hash values clash",
		},
		{
			name: "ReferenceWithoutLocation",
			group: &api.PolicyGroup{
				Id: "no-location-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1,
									// Location is nil
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				// Should be filtered out
				assert.Empty(t, refs)
			},
		},
		{
			name: "ReferenceWithEmptyURI",
			group: &api.PolicyGroup{
				Id: "empty-uri-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "", // Empty URI
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				// Should be filtered out
				assert.Empty(t, refs)
			},
		},
		{
			name: "MultipleDigestAlgorithms",
			group: &api.PolicyGroup{
				Id: "multi-digest-group",
				Blocks: []*api.PolicyBlock{
					{
						Id: "block-1",
						Policies: []*api.Policy{
							{
								Id: "policy-1",
								Source: &api.PolicyRef{
									Id:      "remote-policy-1",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha256": "abc123",
										},
									},
								},
							},
							{
								Id: "policy-2",
								Source: &api.PolicyRef{
									Id:      "remote-policy-2",
									Version: 1,
									Location: &intoto.ResourceDescriptor{
										Uri: "https://example.com/policy.json",
										Digest: map[string]string{
											"sha512": "xyz789",
										},
									},
								},
							},
						},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, refs []api.RemoteReference) {
				require.Len(t, refs, 1)
				// Both digest algorithms should be merged
				digest := refs[0].GetLocation().GetDigest()
				assert.Equal(t, "abc123", digest["sha256"])
				assert.Equal(t, "xyz789", digest["sha512"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			impl := &defaultCompilerImpl{}
			opts := &CompilerOptions{}

			refs, err := impl.ExtractRemotePolicyGroupReferences(opts, tt.group)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, refs)
				}
			}
		})
	}
}
