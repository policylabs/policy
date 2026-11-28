// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package options

type CompileOptions struct {
	ParseOptions

	// Location is where the document being compiled was read from. The
	// self references of the document ("$/" references) resolve against
	// it: they are read in its repository, at its revision. The compiler
	// sets it when it reads the document itself, see WithLocation.
	Location string
}

var DefaultCompileOptions = CompileOptions{
	ParseOptions: DefaultParseOptions,
}

// WithLocation tells the compiler where the document it is handed was read
// from, for the self references ("$/" references) in it to resolve against.
// It is for callers that read a document themselves and compile its data or
// its parsed form: compiling a location sets it. Without it, a document
// with self references does not compile.
func WithLocation(location string) OptFn {
	return func(opts Options) error {
		o, ok := opts.(*CompileOptions)
		if !ok {
			return ErrUnsupportedOptionsType
		}
		o.Location = location
		return nil
	}
}
