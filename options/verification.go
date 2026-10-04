// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"github.com/policylabs/signer/key"
)

type VerificationOptions struct {
	PublicKeys      []key.PublicKeyProvider
	IdentityStrings []string
}

var DefaultVerificationOptions = VerificationOptions{}

func WithPublicKey(keys ...key.PublicKeyProvider) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.PublicKeys = append(o.PublicKeys, keys...)
		case *CompileOptions:
			o.PublicKeys = append(o.PublicKeys, keys...)
		case *VerificationOptions:
			o.PublicKeys = append(o.PublicKeys, keys...)
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

func WithIdentityString(istrings ...string) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.IdentityStrings = append(o.IdentityStrings, istrings...)
		case *CompileOptions:
			o.IdentityStrings = append(o.IdentityStrings, istrings...)
		case *VerificationOptions:
			o.IdentityStrings = append(o.IdentityStrings, istrings...)
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}
