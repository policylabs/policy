// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

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

// testGroup returns a group of one policy read from the uri.
func testGroup(uri string) string {
	return fmt.Sprintf(
		`{"id": "group", "meta": {}, "blocks": [{"id": "b1", "policies": [{"source": {"location": {"uri": %q}}}]}]}`, uri,
	)
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
		"groups/group.json":    testGroup("$/policies/leaf.json"),
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
		"groups/group.json":  testGroup("$/policies/leaf.json"),
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
