// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/policy/predicate"
)

// The statement a signer wraps material in carries the kind's predicate
// type, for all three kinds.
func TestSignerStatementPerKind(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"policy", `{"id": "p", "meta": {"description": "a policy"}, "tenets": [{"id": "t1", "code": "true"}]}`, string(predicate.PolicyPredicateType)},
		{"policyset", `{"id": "s", "meta": {"description": "a set"}, "policies": [{"id": "p", "tenets": [{"id": "t1", "code": "true"}]}]}`, string(predicate.PolicySetPredicateType)},
		{"policygroup", `{"id": "g", "meta": {"description": "a group"}, "blocks": [{"id": "b", "policies": [{"id": "p", "tenets": [{"id": "t1", "code": "true"}]}]}]}`, string(predicate.PolicyGroupPredicateType)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			statement, err := NewSigner().Statement([]byte(tc.data))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(statement.GetPredicateType()))
			require.NotNil(t, statement.GetPredicate())
		})
	}
	_, err := NewSigner().Statement([]byte(`{"not": "policy material"}`))
	require.Error(t, err)
}
