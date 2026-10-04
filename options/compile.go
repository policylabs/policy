// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package options

type CompileOptions struct {
	ParseOptions
}

var DefaultCompileOptions = CompileOptions{
	ParseOptions: DefaultParseOptions,
}
