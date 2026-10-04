// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"fmt"
	"slices"
)

var ContextTypes = []string{
	ContextTypeBool,
	ContextTypeString,
	ContextTypeInt,
}

const (
	ContextTypeBool   = "bool"
	ContextTypeString = "string"
	ContextTypeInt    = "int"
)

// Validate checks if the context is valid
func (cv *ContextVal) Validate() error {
	if cv.GetType() != "" && !slices.Contains(ContextTypes, cv.GetType()) {
		return fmt.Errorf("invalid context type: %q", cv.GetType())
	}
	if cv.Value != nil && cv.Expression != nil {
		return fmt.Errorf("context value cannot define both `value` and `expression`")
	}
	if cv.Default != nil && cv.Expression != nil {
		return fmt.Errorf("context value cannot define both `default` and `expression`")
	}
	if cv.Expression == nil && cv.GetRuntime() != "" {
		return fmt.Errorf("context value `runtime` is only valid when `expression` is set")
	}
	return nil
}

// Merge merges the values set in cv2 into cv. If values are not set nothing
// is replaced.
//
// Static (value/default) and dynamic (expression/runtime) forms are mutually
// exclusive, so when cv2 introduces one form, any stale fields of the other
// form on cv are cleared before applying cv2's values. This keeps a merged
// ContextVal within the shape Validate() accepts.
func (cv *ContextVal) Merge(cv2 *ContextVal) {
	switch {
	case cv2.Expression != nil:
		cv.Value = nil
		cv.Default = nil
	case cv2.Value != nil || cv2.Default != nil:
		cv.Expression = nil
		cv.Runtime = nil
	}

	if v := cv2.Default; v != nil {
		cv.Default = v
	}
	if v := cv2.Value; v != nil {
		cv.Value = v
	}
	if v := cv2.Required; v != nil {
		cv.Required = v
	}
	if v := cv2.Expression; v != nil {
		cv.Expression = v
	}
	if v := cv2.Runtime; v != nil {
		cv.Runtime = v
	}
}
