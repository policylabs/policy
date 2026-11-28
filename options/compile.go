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

	// SelfRoot is the directory the self references of a document read
	// from a local file are read from. Without it, it is the root of the
	// git repository the file is in. See WithSelfRoot.
	SelfRoot string
}

var DefaultCompileOptions = CompileOptions{
	ParseOptions: DefaultParseOptions,
}

// WithLocation tells the compiler where the document it is handed was read
// from, for the self references ("$/" references) in it to resolve against.
// It is for callers that read a document themselves and compile its data or
// its parsed form: compiling a location or a file sets it. The location is
// one the compiler can fetch, or the path of a local file. Without it, a
// document with self references does not compile.
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

// WithSelfRoot sets the directory the self references ("$/" references) of
// a document read from a local file are read from, in place of the root of
// the git repository the file is in. It is enough by itself, with no
// location, to compile the data of a document with self references. It has
// no effect on a document read from a remote location.
func WithSelfRoot(dir string) OptFn {
	return func(opts Options) error {
		o, ok := opts.(*CompileOptions)
		if !ok {
			return ErrUnsupportedOptionsType
		}
		o.SelfRoot = dir
		return nil
	}
}
