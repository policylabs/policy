// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPolicyRefValidate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		mustErr bool
		ref     *PolicyRef
	}{
		{
			"http-requires-hash", true,
			&PolicyRef{
				Location: &intoto.ResourceDescriptor{
					Uri: "http://example.com",
				},
			},
		},
		{
			"vcslocator-requires-hash", true,
			&PolicyRef{
				Location: &intoto.ResourceDescriptor{
					Uri: "git+http://github.com/example",
				},
			},
		},
		{
			"vcslocator-with-digest", false,
			&PolicyRef{
				Location: &intoto.ResourceDescriptor{
					Uri:    "git+http://github.com/example",
					Digest: map[string]string{"sha256": "2347962367823768"},
				},
			},
		},
		{
			"vcslocator-with-commit", false,
			&PolicyRef{
				Location: &intoto.ResourceDescriptor{
					Uri: "git+http://github.com/example@59c8563ff26810478b6ab8ff4c779b4e14385392",
				},
			},
		},
		{
			"invalid-hash-algos", true,
			&PolicyRef{
				Location: &intoto.ResourceDescriptor{
					Digest: map[string]string{"sha2000-deluxe": "59c8563ff26810478b6ab8ff4c779b4e14385392"},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.ref.Validate()
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestParseIdentitySlug(t *testing.T) {
	modeRegexp := SigstoreModeRegexp
	t.Parallel()
	for _, tt := range []struct {
		name    string
		slug    string
		mustErr bool
		expect  *sapi.Identity
	}{
		{
			"sigstore",
			"sigstore::https://token.actions.githubusercontent.com::https://github.com/slsa-framework/slsa-source-poc/.github/workflows/release.yaml@refs/tags/v0.6.1",
			false,
			&sapi.Identity{
				Sigstore: &sapi.IdentitySigstore{
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/slsa-framework/slsa-source-poc/.github/workflows/release.yaml@refs/tags/v0.6.1",
				},
			},
		},
		{
			"sigstore-regexp",
			"sigstore(regexp)::https://token.actions.githubusercontent.com::https://github.com/slsa-framework/slsa-source-poc/.github/workflows/release.yaml@refs/tags/v0.6.1",
			false,
			&sapi.Identity{
				Sigstore: &sapi.IdentitySigstore{
					Mode:     &modeRegexp,
					Issuer:   "https://token.actions.githubusercontent.com",
					Identity: "https://github.com/slsa-framework/slsa-source-poc/.github/workflows/release.yaml@refs/tags/v0.6.1",
				},
			},
		},
		{
			"key",
			"key::ed25519::c6d8e2f4g7h9i1j3k5l7m9n2o4p6q8r1s3t5u7v9w2x4y6z8a1b3c5d7e9f1a3b5",
			false,
			&sapi.Identity{
				Key: &sapi.IdentityKey{
					Type: "ed25519",
					Id:   "c6d8e2f4g7h9i1j3k5l7m9n2o4p6q8r1s3t5u7v9w2x4y6z8a1b3c5d7e9f1a3b5",
				},
			},
		},
		{
			"ref",
			"ref:my-key",
			false,
			&sapi.Identity{Ref: &sapi.IdentityRef{Id: "my-key"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res, err := sapi.NewIdentityFromSpec(tt.slug)
			if tt.mustErr {
				require.Error(t, err)
			}
			require.NoError(t, err)
			require.True(t, proto.Equal(tt.expect, res), "want: %v got: %v", tt.expect, res)
		})
	}
}
