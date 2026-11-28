// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
)

// testPolicy returns a policy document whose tenet carries a marker, to
// tell which copy of a file a compile read.
func testPolicy(marker string) string {
	return fmt.Sprintf(
		`{"id": "leaf", "meta": {"description": "leaf"}, "tenets": [{"id": "t1", "code": "true", "title": %q}]}`, marker,
	)
}

// testSet returns a set of one policy read from the uri.
func testSet(uri string) string {
	return fmt.Sprintf(`{"id": "set", "meta": {}, "policies": [{"source": {"location": {"uri": %q}}}]}`, uri)
}

// testGroup returns a group of one policy, read from a self reference.
func testGroup() string {
	return `{"id": "group", "meta": {}, "blocks": [{"id": "b1", "policies": [` +
		`{"source": {"location": {"uri": "$/policies/leaf.json"}}}]}]}`
}

var noVerify = options.WithVerifySignatures(false)

// TestCompileSelfReferenceSameRevision checks that the self references of a
// document read from a repository are read at the revision of the document:
// the commit its locator names, or the one its branch pointed to when the
// compile started.
func TestCompileSelfReferenceSameRevision(t *testing.T) {
	t.Parallel()
	tr := newTestRepo(t)
	first := tr.commit(map[string]string{
		"sets/set.json":        testSet("$/policies/leaf.json"),
		"policies/leaf.json":   testPolicy("first"),
		"sets/leaf.json":       testPolicy("not relative to the document"),
		"policies/policy.json": `{"id": "wrapper", "source": {"location": {"uri": "$/policies/leaf.json"}}}`,
		"groups/group.json":    testGroup(),
	})
	second := tr.commit(map[string]string{"policies/leaf.json": testPolicy("second")})

	for _, tc := range []struct {
		name     string
		revision string
		commit   string
		marker   string
	}{
		{"commit", first, first, "first"},
		{"default-branch", "", second, "second"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set, _, _, err := NewCompiler().CompileLocation(tr.locator(tc.revision, "sets/set.json"), noVerify)
			require.NoError(t, err)
			require.Len(t, set.GetPolicies(), 1)
			p := set.GetPolicies()[0]
			require.Nil(t, p.GetSource(), "the reference is inlined")
			require.Equal(t, tc.marker, p.GetTenets()[0].GetTitle())
			// The inlined policy records the full location it was read from
			require.Equal(t, tr.locator(tc.commit, "policies/leaf.json"), p.GetMeta().GetOrigin().GetDownloadLocation())

			_, pcy, _, err := NewCompiler().CompileLocation(tr.locator(tc.revision, "policies/policy.json"), noVerify)
			require.NoError(t, err)
			require.Equal(t, tc.marker, pcy.GetTenets()[0].GetTitle())

			_, _, grp, err := NewCompiler().CompileLocation(tr.locator(tc.revision, "groups/group.json"), noVerify)
			require.NoError(t, err)
			require.Equal(t, tc.marker, grp.GetBlocks()[0].GetPolicies()[0].GetTenets()[0].GetTitle())
		})
	}

	t.Run("pinned-references-required", func(t *testing.T) {
		t.Parallel()
		set, _, _, err := NewCompiler(WithPinnedReferences(true)).CompileLocation(
			tr.locator(first, "sets/set.json"), noVerify,
		)
		require.NoError(t, err, "a self reference is pinned by its document")
		require.Equal(t, "first", set.GetPolicies()[0].GetTenets()[0].GetTitle())
	})
}

// TestCompileSelfReferenceNested checks that a self reference in a fetched
// document is read from the repository of that document, at its revision,
// and not from the repository of the document referencing it.
func TestCompileSelfReferenceNested(t *testing.T) {
	t.Parallel()
	inner := newTestRepo(t)
	innerFirst := inner.commit(map[string]string{
		"groups/group.json":  testGroup(),
		"policies/leaf.json": testPolicy("inner first"),
	})
	inner.commit(map[string]string{"policies/leaf.json": testPolicy("inner second")})

	outerSet := func(groupLocator string) string {
		return fmt.Sprintf(`{"id": "set", "meta": {}, "groups": [{"source": {"location": {"uri": %q}}}]}`, groupLocator)
	}
	outer := newTestRepo(t)
	outer.commit(map[string]string{
		"pinned.json":        outerSet(inner.locator(innerFirst, "groups/group.json")),
		"unpinned.json":      outerSet(inner.locator("", "groups/group.json")),
		"policies/leaf.json": testPolicy("outer"),
	})

	for file, marker := range map[string]string{
		"pinned.json": "inner first",
		// A document referenced without a commit is pinned to the one its
		// branch points to, and its self references are read there.
		"unpinned.json": "inner second",
	} {
		set, _, _, err := NewCompiler().CompileLocation(outer.locator("", file), noVerify)
		require.NoError(t, err, file)
		require.Len(t, set.GetGroups(), 1, file)
		require.Equal(t, marker, set.GetGroups()[0].GetBlocks()[0].GetPolicies()[0].GetTenets()[0].GetTitle(), file)
	}
}

// TestCompileSelfReferenceLocation checks where the base of a self
// reference comes from and what happens when there is none to use.
func TestCompileSelfReferenceLocation(t *testing.T) {
	t.Parallel()
	tr := newTestRepo(t)
	commit := tr.commit(map[string]string{"policies/leaf.json": testPolicy("repo")})
	setData := []byte(testSet("$/policies/leaf.json"))

	t.Run("data-with-location", func(t *testing.T) {
		t.Parallel()
		set, _, _, err := NewCompiler().Compile(
			setData, noVerify, options.WithLocation(tr.locator(commit, "sets/set.json")),
		)
		require.NoError(t, err)
		require.Equal(t, "repo", set.GetPolicies()[0].GetTenets()[0].GetTitle())
	})

	t.Run("parsed-with-location", func(t *testing.T) {
		t.Parallel()
		set, err := NewParser().ParsePolicySet(setData)
		require.NoError(t, err)
		set, err = NewCompiler().CompileSet(set, options.WithLocation(tr.locator("", "sets/set.json")))
		require.NoError(t, err)
		require.Equal(t, "repo", set.GetPolicies()[0].GetTenets()[0].GetTitle())
	})

	t.Run("no-location", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := NewCompiler().Compile(setData, noVerify)
		require.ErrorIs(t, err, ErrSelfReferenceUnresolved)
	})

	// A location that is not in a repository, such as a URL, has no
	// revision to read a self reference at.
	t.Run("not-in-a-repository", func(t *testing.T) {
		t.Parallel()
		mem := &memFetcher{scheme: "mem", docs: map[string][]byte{
			"mem://set":                setData,
			"mem://policies/leaf.json": []byte(testPolicy("mem")),
			"mem://outer":              []byte(testSet("mem://set")),
		}}
		_, _, _, err := NewCompiler(WithFetcher(mem)).CompileLocation("mem://set", noVerify)
		require.ErrorIs(t, err, ErrSelfReferenceUnsupported)

		// ... and neither does a document fetched from one
		_, _, _, err = NewCompiler(WithFetcher(mem)).CompileLocation("mem://outer", noVerify)
		require.ErrorIs(t, err, ErrSelfReferenceUnsupported)
		require.Equal(t, [][]string{{"mem://set"}}, mem.groups, "nothing is fetched for the self reference")

		_, _, _, err = NewCompiler().Compile(setData, noVerify, options.WithLocation("https://example.com/sets/set.json"))
		require.ErrorIs(t, err, ErrSelfReferenceUnsupported)
	})

	// The document does not choose where its self references are read from
	t.Run("download-location-is-replaced", func(t *testing.T) {
		t.Parallel()
		other := newTestRepo(t)
		otherCommit := other.commit(map[string]string{"policies/leaf.json": testPolicy("other")})
		data := fmt.Appendf(nil,
			`{"id": "set", "meta": {}, "policies": [{"source": {"location": {"uri": "$/policies/leaf.json", "downloadLocation": %q}}}]}`,
			other.locator(otherCommit, "policies/leaf.json"),
		)
		set, _, _, err := NewCompiler().Compile(data, noVerify, options.WithLocation(tr.locator(commit, "set.json")))
		require.NoError(t, err)
		require.Equal(t, "repo", set.GetPolicies()[0].GetTenets()[0].GetTitle())

		_, _, _, err = NewCompiler().Compile(data, noVerify)
		require.ErrorIs(t, err, ErrSelfReferenceUnresolved)
	})

	t.Run("missing-file", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := NewCompiler().Compile(
			[]byte(testSet("$/policies/nope.json")), noVerify, options.WithLocation(tr.locator(commit, "set.json")),
		)
		require.Error(t, err)
	})
}

// localTree writes files, given by their path, under a new directory made
// to look like the root of a git repository, and returns the directory.
func localTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, files)
	// A worktree has a .git file where a repository has a directory
	writeTree(t, dir, map[string]string{".git": "gitdir: /somewhere/else\n"})
	return dir
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
}

// TestCompileSelfReferenceLocalFile checks that the self references of a
// document read from a local file are read from the working tree of the
// repository the file is in, whatever is committed, and that what gets
// inlined records no commit and no path of the machine.
func TestCompileSelfReferenceLocalFile(t *testing.T) {
	t.Parallel()
	leaf := testPolicy("working tree")
	dir := localTree(t, map[string]string{
		"sets/slsa/set.json":   testSet("$/policies/leaf.json"),
		"sets/nested.json":     `{"id": "set", "meta": {}, "groups": [{"source": {"location": {"uri": "$/groups/group.json"}}}]}`,
		"groups/group.json":    testGroup(),
		"policies/leaf.json":   leaf,
		"policies/policy.json": `{"id": "wrapper", "source": {"location": {"uri": "$/policies/leaf.json"}}}`,
		"sets/slsa/leaf.json":  testPolicy("not relative to the document"),
	})
	sum := sha256.Sum256([]byte(leaf))

	t.Run("set", func(t *testing.T) {
		t.Parallel()
		for _, compile := range []func() (*api.PolicySet, error){
			func() (*api.PolicySet, error) {
				set, _, _, err := NewCompiler().CompileFile(filepath.Join(dir, "sets", "slsa", "set.json"), noVerify)
				return set, err
			},
			func() (*api.PolicySet, error) {
				set, _, _, err := NewCompiler().CompileLocation(filepath.Join(dir, "sets", "slsa", "set.json"), noVerify)
				return set, err
			},
		} {
			set, err := compile()
			require.NoError(t, err)
			require.Len(t, set.GetPolicies(), 1)
			p := set.GetPolicies()[0]
			require.Nil(t, p.GetSource(), "the reference is inlined")
			require.Equal(t, "working tree", p.GetTenets()[0].GetTitle())

			origin := p.GetMeta().GetOrigin()
			require.Equal(t, "$/policies/leaf.json", origin.GetUri())
			require.Empty(t, origin.GetDownloadLocation())
			require.Equal(t, hex.EncodeToString(sum[:]), origin.GetDigest()["sha256"])
		}
	})

	t.Run("policy", func(t *testing.T) {
		t.Parallel()
		_, pcy, _, err := NewCompiler().CompileFile(filepath.Join(dir, "policies", "policy.json"), noVerify)
		require.NoError(t, err)
		require.Equal(t, "working tree", pcy.GetTenets()[0].GetTitle())
	})

	t.Run("group", func(t *testing.T) {
		t.Parallel()
		_, _, grp, err := NewCompiler().CompileFile(filepath.Join(dir, "groups", "group.json"), noVerify)
		require.NoError(t, err)
		require.Equal(t, "working tree", grp.GetBlocks()[0].GetPolicies()[0].GetTenets()[0].GetTitle())
	})

	// The self references of a file read from the repository are files of
	// the repository too.
	t.Run("nested", func(t *testing.T) {
		t.Parallel()
		set, _, _, err := NewCompiler().CompileFile(filepath.Join(dir, "sets", "nested.json"), noVerify)
		require.NoError(t, err)
		require.Equal(t, "working tree", set.GetGroups()[0].GetBlocks()[0].GetPolicies()[0].GetTenets()[0].GetTitle())
	})

	t.Run("pinned-references-required", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := NewCompiler(WithPinnedReferences(true)).CompileFile(
			filepath.Join(dir, "sets", "nested.json"), noVerify,
		)
		require.NoError(t, err)
	})

	t.Run("missing-file", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := NewCompiler().Compile(
			[]byte(testSet("$/policies/nope.json")), noVerify, options.WithSelfRoot(dir),
		)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("size-limit", func(t *testing.T) {
		t.Parallel()
		compiler := NewCompiler()
		compiler.Fetcher = NewFetcherWithLimits(options.Limits{MaxInputSize: int64(len(leaf) - 1)})
		_, _, _, err := compiler.Compile([]byte(testSet("$/policies/leaf.json")), noVerify, options.WithSelfRoot(dir))
		var limit *options.LimitError
		require.ErrorAs(t, err, &limit)
	})
}

// TestCompileSelfReferenceLocalRoot checks how the directory the self
// references of a local file are read from is found.
func TestCompileSelfReferenceLocalRoot(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"sets/set.json":      testSet("$/policies/leaf.json"),
		"policies/leaf.json": testPolicy("tree"),
	}

	t.Run("not-in-a-repository", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeTree(t, dir, files)
		_, _, _, err := NewCompiler().CompileFile(filepath.Join(dir, "sets", "set.json"), noVerify)
		require.ErrorIs(t, err, ErrSelfReferenceUnresolved)
		require.ErrorContains(t, err, "not in a git repository")

		// ... unless the caller names the root
		set, _, _, err := NewCompiler().CompileFile(
			filepath.Join(dir, "sets", "set.json"), noVerify, options.WithSelfRoot(dir),
		)
		require.NoError(t, err)
		require.Equal(t, "tree", set.GetPolicies()[0].GetTenets()[0].GetTitle())
	})

	t.Run("root-overrides-repository", func(t *testing.T) {
		t.Parallel()
		dir := localTree(t, files)
		other := t.TempDir()
		writeTree(t, other, map[string]string{"policies/leaf.json": testPolicy("other")})
		set, _, _, err := NewCompiler().CompileFile(
			filepath.Join(dir, "sets", "set.json"), noVerify, options.WithSelfRoot(other),
		)
		require.NoError(t, err)
		require.Equal(t, "other", set.GetPolicies()[0].GetTenets()[0].GetTitle())
	})

	t.Run("closest-repository", func(t *testing.T) {
		t.Parallel()
		dir := localTree(t, map[string]string{"policies/leaf.json": testPolicy("outer")})
		writeTree(t, filepath.Join(dir, "vendor", "inner"), files)
		writeTree(t, filepath.Join(dir, "vendor", "inner"), map[string]string{".git/HEAD": "ref: refs/heads/main\n"})
		set, _, _, err := NewCompiler().CompileFile(
			filepath.Join(dir, "vendor", "inner", "sets", "set.json"), noVerify,
		)
		require.NoError(t, err)
		require.Equal(t, "tree", set.GetPolicies()[0].GetTenets()[0].GetTitle())
	})

	t.Run("location-of-unknown-scheme", func(t *testing.T) {
		t.Parallel()
		_, _, _, err := NewCompiler().Compile(
			[]byte(files["sets/set.json"]), noVerify, options.WithLocation("unknown://host/sets/set.json"),
		)
		require.ErrorIs(t, err, ErrSelfReferenceUnsupported)
	})
}

// TestCompileSelfReferenceLocalBoundaries checks that reading self
// references from disk stays inside the repository, and that only the
// documents read from disk get to do it.
func TestCompileSelfReferenceLocalBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("symlink-out-of-the-repository", func(t *testing.T) {
		t.Parallel()
		outside := t.TempDir()
		writeTree(t, outside, map[string]string{"leaf.json": testPolicy("outside")})
		dir := localTree(t, map[string]string{"sets/set.json": testSet("$/policies/leaf.json")})
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "policies"), 0o750))
		require.NoError(t, os.Symlink(filepath.Join(outside, "leaf.json"), filepath.Join(dir, "policies", "leaf.json")))

		_, _, _, err := NewCompiler().CompileFile(filepath.Join(dir, "sets", "set.json"), noVerify)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "outside")
	})

	// A document fetched from a repository reads its self references
	// there, even when the local repository has a file at the same path.
	t.Run("fetched-document-reads-its-own-repository", func(t *testing.T) {
		t.Parallel()
		remote := newTestRepo(t)
		commit := remote.commit(map[string]string{
			"groups/group.json": testGroup(),
			// The store refuses two policies sharing an id
			"policies/leaf.json": strings.Replace(testPolicy("remote"), `"leaf"`, `"remote-leaf"`, 1),
		})
		dir := localTree(t, map[string]string{
			"policies/leaf.json": testPolicy("local"),
			"sets/set.json": fmt.Sprintf(
				`{"id": "set", "meta": {}, "policies": [{"source": {"location": {"uri": "$/policies/leaf.json"}}}],
				"groups": [{"source": {"location": {"uri": %q}}}]}`, remote.locator(commit, "groups/group.json"),
			),
		})
		set, _, _, err := NewCompiler().CompileFile(filepath.Join(dir, "sets", "set.json"), noVerify)
		require.NoError(t, err)
		require.Equal(t, "local", set.GetPolicies()[0].GetTenets()[0].GetTitle())
		fetched := set.GetGroups()[0].GetBlocks()[0].GetPolicies()[0]
		require.Equal(t, "remote", fetched.GetTenets()[0].GetTitle())
		require.Equal(t, remote.locator(commit, "policies/leaf.json"), fetched.GetMeta().GetOrigin().GetDownloadLocation())
	})

	// A fetched document that is not in a repository cannot reach the
	// local one through a self reference.
	t.Run("fetched-document-does-not-read-local-files", func(t *testing.T) {
		t.Parallel()
		mem := &memFetcher{scheme: "mem", docs: map[string][]byte{
			"mem://group": []byte(testGroup()),
		}}
		dir := localTree(t, map[string]string{
			"policies/leaf.json": testPolicy("local"),
			"sets/set.json":      `{"id": "set", "meta": {}, "groups": [{"source": {"location": {"uri": "mem://group"}}}]}`,
		})
		_, _, _, err := NewCompiler(WithFetcher(mem)).CompileFile(filepath.Join(dir, "sets", "set.json"), noVerify)
		require.ErrorIs(t, err, ErrSelfReferenceUnsupported)
	})

	// Files referencing each other end the compile with an error
	t.Run("cycle", func(t *testing.T) {
		t.Parallel()
		dir := localTree(t, map[string]string{
			"a.json": `{"id": "a", "source": {"location": {"uri": "$/b.json"}}}`,
			"b.json": `{"id": "b", "source": {"location": {"uri": "$/a.json"}}}`,
		})
		_, _, _, err := NewCompiler().CompileFile(filepath.Join(dir, "a.json"), noVerify)
		require.Error(t, err)
	})
}
