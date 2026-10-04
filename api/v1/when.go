// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"strings"
)

// IsSet reports if the condition gates evaluation. A nil When or one with an
// empty expression means the policy or block always evaluates.
func (w *When) IsSet() bool {
	return w != nil && strings.TrimSpace(w.GetExpression()) != ""
}

// Validate checks the structure of the condition: a runtime is only
// meaningful with an expression. The expression itself is not inspected
// here; it is checked by the runtime that evaluates it, which is also where
// references to context values that are not defined in scope fail.
func (w *When) Validate() error {
	if w == nil {
		return nil
	}
	if !w.IsSet() && w.GetRuntime() != "" {
		return errors.New("`when` runtime is only valid when `expression` is set")
	}
	return nil
}
