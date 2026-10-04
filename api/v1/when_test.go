// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWhenValidate(t *testing.T) {
	t.Parallel()
	var none *When
	require.NoError(t, none.Validate(), "no condition always evaluates")
	require.False(t, none.IsSet())
	require.NoError(t, (&When{}).Validate())
	require.False(t, (&When{Expression: "  "}).IsSet(), "blank expressions mean always")
	require.True(t, (&When{Expression: "context.env == 'prod'"}).IsSet())
	require.NoError(t, (&When{Expression: "true", Runtime: "cel@v0"}).Validate())
	require.ErrorContains(t, (&When{Runtime: "cel@v0"}).Validate(), "runtime")
}
