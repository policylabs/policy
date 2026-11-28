// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/carabiner-dev/vcslocator"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

// testRepo is a git repository on disk that tests reach with git+file
// locators.
type testRepo struct {
	t    *testing.T
	dir  string
	repo *git.Repository
}

func newTestRepo(t *testing.T) *testRepo {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	return &testRepo{t: t, dir: dir, repo: repo}
}

func (tr *testRepo) signature() *object.Signature {
	return &object.Signature{Name: "Test", Email: "test@example.com", When: time.Unix(1700000000, 0)}
}

// commit writes the files, given by their path in the repository, and
// commits them. It returns the name of the commit.
func (tr *testRepo) commit(files map[string]string) string {
	tr.t.Helper()
	wt, err := tr.repo.Worktree()
	require.NoError(tr.t, err)
	for name, content := range files {
		path := filepath.Join(tr.dir, filepath.FromSlash(name))
		require.NoError(tr.t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(tr.t, os.WriteFile(path, []byte(content), 0o600))
		_, err := wt.Add(name)
		require.NoError(tr.t, err)
	}
	hash, err := wt.Commit("change", &git.CommitOptions{Author: tr.signature()})
	require.NoError(tr.t, err)
	return hash.String()
}

// branch creates a branch pointing to the commit.
func (tr *testRepo) branch(name, commit string) {
	tr.t.Helper()
	require.NoError(tr.t, tr.repo.Storer.SetReference(
		plumbing.NewHashReference(plumbing.NewBranchReferenceName(name), plumbing.NewHash(commit)),
	))
}

// tag creates a tag of the commit, annotated when it has a message.
func (tr *testRepo) tag(name, commit, message string) {
	tr.t.Helper()
	var opts *git.CreateTagOptions
	if message != "" {
		opts = &git.CreateTagOptions{Tagger: tr.signature(), Message: message}
	}
	_, err := tr.repo.CreateTag(name, plumbing.NewHash(commit), opts)
	require.NoError(tr.t, err)
}

// locator returns the locator of a path of the repository at a revision,
// both optional.
func (tr *testRepo) locator(revision, path string) string {
	l := "git+file://" + filepath.ToSlash(tr.dir)
	if revision != "" {
		l += "@" + revision
	}
	if path != "" {
		l += "#" + path
	}
	return l
}

func TestVCSFetcherPinLocation(t *testing.T) {
	t.Parallel()
	tr := newTestRepo(t)
	first := tr.commit(map[string]string{"sets/set.json": "{}"})
	second := tr.commit(map[string]string{"sets/set.json": `{"id": "set"}`})
	tr.branch("old", first)
	tr.tag("v1", first, "")
	tr.tag("v1-annotated", first, "release v1")

	for _, tc := range []struct {
		name     string
		revision string
		commit   string
	}{
		{"default-branch", "", second},
		{"branch", "old", first},
		{"branch-full-name", "refs/heads/old", first},
		{"tag", "v1", first},
		{"tag-full-name", "refs/tags/v1", first},
		// An annotated tag resolves to its commit, not to the tag object
		{"annotated-tag", "v1-annotated", first},
		{"commit", first, first},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pinned, err := NewFetcher().PinLocation(context.Background(), tr.locator(tc.revision, "sets/set.json"))
			require.NoError(t, err)
			require.Equal(t, tr.locator(tc.commit, "sets/set.json"), pinned)
		})
	}

	t.Run("unknown-revision", func(t *testing.T) {
		t.Parallel()
		_, err := NewFetcher().PinLocation(context.Background(), tr.locator("nope", "sets/set.json"))
		require.ErrorIs(t, err, vcslocator.ErrRefNotFound)
	})

	t.Run("pinned-is-not-looked-up", func(t *testing.T) {
		t.Parallel()
		// Nothing answers at this address, a lookup would fail.
		const loc = "git+https://localhost:1/org/repo@59c8563ff26810478b6ab8ff4c779b4e14385392#p.json"
		pinned, err := NewFetcher().PinLocation(context.Background(), loc)
		require.NoError(t, err)
		require.Equal(t, loc, pinned)
	})

	t.Run("plain-url-is-left-alone", func(t *testing.T) {
		t.Parallel()
		const loc = "https://example.com/sets/set.json"
		pinned, err := NewFetcher().PinLocation(context.Background(), loc)
		require.NoError(t, err)
		require.Equal(t, loc, pinned)
	})
}

func TestFetcherResolveSelf(t *testing.T) {
	t.Parallel()
	const commit = "59c8563ff26810478b6ab8ff4c779b4e14385392"
	for _, tc := range []struct {
		name     string
		base     string
		path     string
		expected string
		mustErr  error
	}{
		{
			"https", "git+https://github.com/org/repo@" + commit + "#sets/set.hjson", "slsa/policy.hjson",
			"git+https://github.com/org/repo@" + commit + "#slsa/policy.hjson", nil,
		},
		{
			"ssh", "git+ssh://github.com/org/repo@" + commit + "#sets/set.hjson", "policy.hjson",
			"git+ssh://github.com/org/repo@" + commit + "#policy.hjson", nil,
		},
		{
			"file", "git+file:///tmp/repo@" + commit + "#set.hjson", "slsa/policy.hjson",
			"git+file:///tmp/repo@" + commit + "#slsa/policy.hjson", nil,
		},
		{
			"base-without-path", "git+https://github.com/org/repo@" + commit, "policy.hjson",
			"git+https://github.com/org/repo@" + commit + "#policy.hjson", nil,
		},
		{"http-url", "https://example.com/sets/set.hjson", "slsa/policy.hjson", "", ErrSelfReferenceUnsupported},
		{"local-path", "sets/set.hjson", "slsa/policy.hjson", "", ErrSelfReferenceUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := NewFetcher().ResolveSelf(tc.base, tc.path)
			if tc.mustErr != nil {
				require.ErrorIs(t, err, tc.mustErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, res)
		})
	}

	// A base that does not name a full commit has no revision to share
	for _, base := range []string{
		"git+https://github.com/org/repo#sets/set.hjson",
		"git+https://github.com/org/repo@main#sets/set.hjson",
		"git+https://github.com/org/repo@59c8563#sets/set.hjson",
	} {
		_, err := NewFetcher().ResolveSelf(base, "slsa/policy.hjson")
		require.Error(t, err, base)
		require.NotErrorIs(t, err, ErrSelfReferenceUnsupported, base)
	}
}

// TestPinnedLocationIsFetchable checks that what PinLocation and
// ResolveSelf build are locators the fetcher reads.
func TestPinnedLocationIsFetchable(t *testing.T) {
	t.Parallel()
	tr := newTestRepo(t)
	tr.commit(map[string]string{"sets/set.json": `{"id": "set"}`, "slsa/policy.json": `{"id": "policy"}`})
	tr.commit(map[string]string{"unrelated": "x"})

	f := NewFetcher()
	pinned, err := f.PinLocation(context.Background(), tr.locator("", "slsa/policy.json"))
	require.NoError(t, err)
	data, err := f.Get(context.Background(), pinned)
	require.NoError(t, err)
	require.JSONEq(t, `{"id": "policy"}`, string(data))

	self, err := f.ResolveSelf(pinned, "sets/set.json")
	require.NoError(t, err)
	data, err = f.Get(context.Background(), self)
	require.NoError(t, err)
	require.JSONEq(t, `{"id": "set"}`, string(data))
}
