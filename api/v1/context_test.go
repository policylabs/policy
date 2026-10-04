// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestContextValValidate(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		sut     *ContextVal
		mustErr bool
	}{
		{"no-value", &ContextVal{Type: ""}, false},
		{"no-value", &ContextVal{Type: "string"}, false},
		{"no-value", &ContextVal{Type: "int"}, false},
		{"no-value", &ContextVal{Type: "bool"}, false},
		{"no-value", &ContextVal{Type: "something-else"}, true},
		{"expression-only", &ContextVal{Expression: ptrString("subject.name")}, false},
		{"expression-and-runtime", &ContextVal{Expression: ptrString("subject.name"), Runtime: ptrString("cel@v0")}, false},
		{"runtime-without-expression", &ContextVal{Runtime: ptrString("cel@v0")}, true},
		{"value-and-expression", &ContextVal{
			Value:      structpb.NewStringValue("x"),
			Expression: ptrString("subject.name"),
		}, true},
		{"default-and-expression", &ContextVal{
			Default:    structpb.NewStringValue("x"),
			Expression: ptrString("subject.name"),
		}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.sut.Validate()
			if tt.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func ptrString(s string) *string { return &s }

func TestContextValMerge(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name  string
		base  *ContextVal
		patch *ContextVal
		want  *ContextVal
	}{
		{
			"expression-clears-static",
			&ContextVal{Value: structpb.NewStringValue("x"), Default: structpb.NewStringValue("y")},
			&ContextVal{Expression: ptrString("subject.name")},
			&ContextVal{Expression: ptrString("subject.name")},
		},
		{
			"value-clears-expression",
			&ContextVal{Expression: ptrString("subject.name"), Runtime: ptrString("cel@v0")},
			&ContextVal{Value: structpb.NewStringValue("x")},
			&ContextVal{Value: structpb.NewStringValue("x")},
		},
		{
			"default-clears-expression",
			&ContextVal{Expression: ptrString("subject.name"), Runtime: ptrString("cel@v0")},
			&ContextVal{Default: structpb.NewStringValue("x")},
			&ContextVal{Default: structpb.NewStringValue("x")},
		},
		{
			"required-does-not-clear-either-form",
			&ContextVal{Expression: ptrString("subject.name")},
			&ContextVal{Required: func() *bool { b := true; return &b }()},
			&ContextVal{Expression: ptrString("subject.name"), Required: func() *bool { b := true; return &b }()},
		},
		{
			"runtime-only-patch-preserves-expression",
			&ContextVal{Expression: ptrString("subject.name")},
			&ContextVal{Runtime: ptrString("cel@v0")},
			&ContextVal{Expression: ptrString("subject.name"), Runtime: ptrString("cel@v0")},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.base.Merge(tt.patch)
			require.NoError(t, tt.base.Validate(), "merged ContextVal must pass Validate()")
			require.Equal(t, tt.want.GetExpression(), tt.base.GetExpression())
			require.Equal(t, tt.want.GetRuntime(), tt.base.GetRuntime())
			if tt.want.Value == nil {
				require.Nil(t, tt.base.Value)
			} else {
				require.NotNil(t, tt.base.Value)
				require.Equal(t, tt.want.Value.AsInterface(), tt.base.Value.AsInterface())
			}
			if tt.want.Default == nil {
				require.Nil(t, tt.base.Default)
			} else {
				require.NotNil(t, tt.base.Default)
				require.Equal(t, tt.want.Default.AsInterface(), tt.base.Default.AsInterface())
			}
		})
	}
}
