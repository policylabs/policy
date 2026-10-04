// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package options

import "errors"

var ErrUnsupportedOptionsType = errors.New("unsupported options type")

type OptFn func(Options) error

type Options any
