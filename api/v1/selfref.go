// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// SelfReferencePrefix starts the URI of a self reference: a reference to a
// file in the same repository, at the same revision, as the document that
// contains it. What follows the prefix is the path of the file from the
// root of the repository:
//
//	$/slsa/slsa-builder-id.hjson
//
// A self reference names no repository and no revision, it takes both from
// the document it is written in. That makes it pinned whenever its document
// is, and lets a set and the policies it is made of change together.
const SelfReferencePrefix = "$/"

// IsSelfReference reports whether a URI is written in the self reference
// notation. It does not check that the reference is well formed, see
// SelfReferencePath.
func IsSelfReference(uri string) bool {
	return strings.HasPrefix(uri, SelfReferencePrefix)
}

// SelfReferencePath returns the path a self reference points to, relative to
// the root of the repository and separated by slashes. It returns an error
// when the URI is not a self reference or when its path is not one that
// stays inside the repository: empty, rooted or with empty, "." or ".."
// elements.
func SelfReferencePath(uri string) (string, error) {
	if !IsSelfReference(uri) {
		return "", fmt.Errorf("%q is not a self reference, it does not start with %q", uri, SelfReferencePrefix)
	}
	p := strings.TrimPrefix(uri, SelfReferencePrefix)

	switch {
	case p == "":
		return "", fmt.Errorf("self reference %q names no file", uri)
	case strings.Contains(p, "@"):
		return "", fmt.Errorf(
			"self reference %q takes no revision: it is read at the revision of the document it is in", uri,
		)
	case strings.ContainsAny(p, `#?\`):
		return "", fmt.Errorf(`self reference %q is not a plain path: it contains one of "#", "?" or "\"`, uri)
	case p == "." || !fs.ValidPath(p):
		return "", fmt.Errorf(
			`self reference %q is not a path from the root of the repository: it has empty, "." or ".." elements`, uri,
		)
	}
	return p, nil
}

// validateSelfReference checks the notation of a reference written as a
// self reference. References of any other kind, and nil ones, pass.
func validateSelfReference(ref RemoteReference) error {
	if ref == nil || ref.GetLocation() == nil {
		return nil
	}

	// The download location is where the compiler records what a self
	// reference resolved to, a document cannot write one there.
	if !IsSelfReference(ref.GetLocation().GetUri()) {
		if IsSelfReference(ref.GetLocation().GetDownloadLocation()) {
			return errors.New("self references are written in the uri of a location, not in its downloadLocation")
		}
		return nil
	}

	_, err := SelfReferencePath(ref.GetLocation().GetUri())
	return err
}
