// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	intoto "github.com/in-toto/attestation/go/v1"

	api "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
)

// referenceLocations returns the location of every reference written in a
// document, the one that is not nil, including those of the policies and
// groups nested in it. They are the descriptors of the document itself, so
// changing one changes the reference.
func referenceLocations(set *api.PolicySet, pcy *api.Policy, grp *api.PolicyGroup) []*intoto.ResourceDescriptor {
	locs := []*intoto.ResourceDescriptor{}
	add := func(ref api.RemoteReference) {
		if l := ref.GetLocation(); l != nil {
			locs = append(locs, l)
		}
	}
	addGroup := func(g *api.PolicyGroup) {
		add(g.GetSource())
		for _, b := range g.GetBlocks() {
			for _, p := range b.GetPolicies() {
				add(p.GetSource())
			}
		}
	}

	switch {
	case set != nil:
		for _, r := range set.GetCommon().GetReferences() {
			add(r)
		}
		for _, p := range set.GetPolicies() {
			add(p.GetSource())
		}
		for _, g := range set.GetGroups() {
			addGroup(g)
		}
	case pcy != nil:
		add(pcy.GetSource())
	case grp != nil:
		addGroup(grp)
	}
	return locs
}

// resolveSelfReferences resolves the self references ("$/" references, see
// api.SelfReferencePrefix) among the locations of the references of a
// document, against where the document was read from.
//
// When base is a location the fetcher handles, each reference resolves to a
// location in the repository and at the revision of base, recorded as the
// download location of the reference, which is where the compiler fetches
// it from. The base is pinned before resolving against it, so that all the
// self references of a document are read at one revision. A base that is
// not in a repository fails with ErrSelfReferenceUnsupported.
//
// Any other base is the path of a local file, and its self references are
// files of the working tree of the repository the file is in: localRoot
// when it is set, or else the closest directory above the file holding a
// .git entry. They are left without a download location, which marks them
// to be read from disk, and the root to read them from is returned.
//
// The uri of a reference is kept as written in both cases, and whatever
// the document wrote as the download location of a self reference is
// dropped: a document never chooses where one is read from. A document
// with self references and neither a base nor a root fails with
// ErrSelfReferenceUnresolved.
func resolveSelfReferences(
	ctx context.Context, fetcher *Fetcher, base, localRoot string, locs []*intoto.ResourceDescriptor,
) (root string, err error) {
	remote := base != "" && fetcher.Supports(base)
	pinned := ""
	for _, loc := range locs {
		if !api.IsSelfReference(loc.GetUri()) {
			continue
		}
		path, err := api.SelfReferencePath(loc.GetUri())
		if err != nil {
			return "", err
		}

		if !remote {
			if root == "" {
				if root, err = localSelfRoot(base, localRoot); err != nil {
					return "", fmt.Errorf("%w: %q", err, loc.GetUri())
				}
			}
			loc.DownloadLocation = ""
			continue
		}

		if pinned == "" {
			if pinned, err = fetcher.PinLocation(ctx, base); err != nil {
				return "", fmt.Errorf("pinning the location of the document: %w", err)
			}
		}
		resolved, err := fetcher.ResolveSelf(pinned, path)
		if err != nil {
			return "", fmt.Errorf("resolving %q: %w", loc.GetUri(), err)
		}
		loc.DownloadLocation = resolved
	}
	return root, nil
}

// isLocalSelfReference reports whether a reference is a self reference
// resolved to a file of the local repository, see resolveSelfReferences.
func isLocalSelfReference(ref api.RemoteReference) bool {
	return api.IsSelfReference(ref.GetLocation().GetUri()) && ref.GetLocation().GetDownloadLocation() == ""
}

// localSelfRoot returns the directory the self references of a local file
// are read from: the root handed in or, without one, the root of the
// repository the file is in.
func localSelfRoot(file, root string) (string, error) {
	if root != "" {
		return root, nil
	}
	if file == "" {
		return "", ErrSelfReferenceUnresolved
	}
	// A location of a scheme no fetcher handles is not a file
	if strings.Contains(file, "://") {
		return "", fmt.Errorf("%w: %q", ErrSelfReferenceUnsupported, file)
	}

	dir, err := filepath.Abs(filepath.Dir(file))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSelfReferenceUnresolved, err)
	}
	for {
		// A .git entry marks the root: a directory in a repository, a file
		// in a worktree or a submodule.
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: %q is not in a git repository", ErrSelfReferenceUnresolved, file)
		}
		dir = parent
	}
}

// readLocalSelfReference reads the file a self reference points to from the
// repository at root. The read cannot leave the root, through the path or
// through a symbolic link, and fails on a file larger than maxSize when
// that is not zero.
func readLocalSelfReference(root, uri string, maxSize int64) ([]byte, error) {
	path, err := api.SelfReferencePath(uri)
	if err != nil {
		return nil, err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("opening the root of the repository: %w", err)
	}
	defer r.Close() //nolint:errcheck // nothing was written

	f, err := r.Open(filepath.FromSlash(path))
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // nothing was written

	if maxSize <= 0 {
		return io.ReadAll(f)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, options.NewInputSizeError(maxSize, int64(len(data)), uri)
	}
	return data, nil
}

// clearOriginDownloadLocation drops the download location from the origin
// of a document, the one that is not nil.
func clearOriginDownloadLocation(set *api.PolicySet, pcy *api.Policy, grp *api.PolicyGroup) {
	switch {
	case set != nil:
		set.GetMeta().GetOrigin().DownloadLocation = ""
	case pcy != nil:
		pcy.GetMeta().GetOrigin().DownloadLocation = ""
	case grp != nil:
		grp.GetMeta().GetOrigin().DownloadLocation = ""
	}
}

// resolveFetchedSelfReferences resolves the self references of a document
// read as a reference, the one that is not nil, against the uri it was read
// from and not against the document referencing it: the local repository
// for a document read from it.
func resolveFetchedSelfReferences(
	ctx context.Context, opts *CompilerOptions, fetcher *Fetcher, uri string,
	set *api.PolicySet, pcy *api.Policy, grp *api.PolicyGroup,
) error {
	base, root := uri, ""
	if api.IsSelfReference(uri) {
		base, root = "", opts.selfRoot
		// A document read from the working tree has no commit to name and
		// records where it came from the way it was referenced.
		clearOriginDownloadLocation(set, pcy, grp)
	}
	if _, err := resolveSelfReferences(ctx, fetcher, base, root, referenceLocations(set, pcy, grp)); err != nil {
		return fmt.Errorf("resolving self references of %q: %w", uri, err)
	}
	return nil
}
