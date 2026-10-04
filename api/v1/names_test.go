// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"buf.build/go/protovalidate"
	"github.com/stretchr/testify/require"
)

// TestMetaNamesAreSingleLine checks that the name of a policy, a policy set
// and a policy group must be a single line.
func TestMetaNamesAreSingleLine(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		good func() error
		bad  func() error
	}{
		{
			"policy",
			func() error { return protovalidate.Validate(&Policy{Meta: &Meta{Name: "SLSA builder id"}}) },
			func() error { return protovalidate.Validate(&Policy{Meta: &Meta{Name: "two\nlines"}}) },
		},
		{
			"policyset",
			func() error { return protovalidate.Validate(&PolicySet{Meta: &PolicySetMeta{Name: "drop release"}}) },
			func() error { return protovalidate.Validate(&PolicySet{Meta: &PolicySetMeta{Name: "two\r\nlines"}}) },
		},
		{
			"policygroup",
			func() error {
				return protovalidate.Validate(&PolicyGroup{Meta: &PolicyGroupMeta{Name: "OSPS baseline"}})
			},
			func() error { return protovalidate.Validate(&PolicyGroup{Meta: &PolicyGroupMeta{Name: "two\nlines"}}) },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, tc.good())
			require.ErrorContains(t, tc.bad(), "name")
		})
	}
}
