// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/carabiner-dev/vcslocator"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	api "github.com/policylabs/policy/api/v1"
)

func TestDigestsMatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		oldDigests map[string]string
		newDigests map[string]string
		want       bool
	}{
		{
			name:       "single-algo-match",
			oldDigests: map[string]string{"sha256": "aaa"},
			newDigests: map[string]string{"sha256": "aaa"},
			want:       true,
		},
		{
			name:       "single-algo-mismatch",
			oldDigests: map[string]string{"sha256": "aaa"},
			newDigests: map[string]string{"sha256": "bbb"},
			want:       false,
		},
		{
			name:       "shared-matches-extras-in-new-ignored",
			oldDigests: map[string]string{"sha256": "aaa"},
			newDigests: map[string]string{"sha256": "aaa", "sha512": "zzz"},
			want:       true,
		},
		{
			name:       "any-shared-mismatch-fails",
			oldDigests: map[string]string{"sha256": "aaa", "sha512": "yyy"},
			newDigests: map[string]string{"sha256": "aaa", "sha512": "zzz"},
			want:       false,
		},
		{
			name:       "no-overlap-returns-false",
			oldDigests: map[string]string{"sha1": "111"},
			newDigests: map[string]string{"sha256": "aaa"},
			want:       false,
		},
		{
			name:       "both-empty-returns-false",
			oldDigests: map[string]string{},
			newDigests: map[string]string{},
			want:       false,
		},
		{
			name:       "old-has-extra-algos-still-match",
			oldDigests: map[string]string{"sha256": "aaa", "sha512": "yyy"},
			newDigests: map[string]string{"sha256": "aaa"},
			want:       true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, digestsMatch(tc.oldDigests, tc.newDigests))
		})
	}
}

func TestHashBytes(t *testing.T) {
	t.Parallel()
	// sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

	t.Run("known-sha256", func(t *testing.T) {
		t.Parallel()
		got, err := hashBytes([]byte("hello"), []string{"sha256"})
		require.NoError(t, err)
		require.Equal(t, want, got["sha256"])
	})

	t.Run("unsupported-algo-skipped", func(t *testing.T) {
		t.Parallel()
		got, err := hashBytes([]byte("hello"), []string{"sha256", "made-up-algo"})
		require.NoError(t, err)
		require.Contains(t, got, "sha256")
		require.NotContains(t, got, "made-up-algo")
	})

	t.Run("only-unsupported-returns-empty", func(t *testing.T) {
		t.Parallel()
		got, err := hashBytes([]byte("hello"), []string{"made-up-algo"})
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

func TestComputeDigests(t *testing.T) {
	t.Parallel()
	t.Run("always-includes-sha256", func(t *testing.T) {
		t.Parallel()
		got, err := computeDigests([]byte("hello"), nil)
		require.NoError(t, err)
		require.Contains(t, got, "sha256")
	})

	t.Run("covers-reference-algorithms", func(t *testing.T) {
		t.Parallel()
		got, err := computeDigests([]byte("hello"), map[string]string{
			"sha256": "old",
			"sha512": "old",
		})
		require.NoError(t, err)
		require.Contains(t, got, "sha256")
		require.Contains(t, got, "sha512")
	})

	t.Run("unknown-reference-algo-skipped", func(t *testing.T) {
		t.Parallel()
		got, err := computeDigests([]byte("hello"), map[string]string{
			"sha256":     "old",
			"bogus-algo": "old",
		})
		require.NoError(t, err)
		require.Contains(t, got, "sha256")
		require.NotContains(t, got, "bogus-algo")
	})
}

func TestBuildLocatorAt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		repo   string
		sub    string
		commit string
		want   string
	}{
		{
			name:   "with-subpath",
			repo:   "/carabiner-dev/policies",
			sub:    "sbom/sbom-exists.json",
			commit: "deadbeef",
			want:   "git+https://github.com/carabiner-dev/policies@deadbeef#sbom/sbom-exists.json",
		},
		{
			name:   "no-subpath",
			repo:   "carabiner-dev/policies",
			sub:    "",
			commit: "deadbeef",
			want:   "git+https://github.com/carabiner-dev/policies@deadbeef",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildLocatorAt(&vcsTestComponents(tc.repo, tc.sub).Components, tc.commit)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestRemoteRefName(t *testing.T) {
	t.Parallel()
	t.Run("branch-wins", func(t *testing.T) {
		t.Parallel()
		c := vcsTestComponents("x/y", "").Components
		c.Branch = "main"
		c.Tag = "v1"
		require.Equal(t, "refs/heads/main", remoteRefName(&c))
	})

	t.Run("tag", func(t *testing.T) {
		t.Parallel()
		c := vcsTestComponents("x/y", "").Components
		c.Tag = "v1.2.3"
		require.Equal(t, "refs/tags/v1.2.3", remoteRefName(&c))
	})

	t.Run("neither-returns-empty", func(t *testing.T) {
		t.Parallel()
		c := vcsTestComponents("x/y", "").Components
		require.Empty(t, remoteRefName(&c))
	})
}

func TestGroupRefToPolicyRef(t *testing.T) {
	t.Parallel()
	t.Run("nil-returns-nil", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, groupRefToPolicyRef(nil))
	})

	t.Run("copies-id-version-and-location", func(t *testing.T) {
		t.Parallel()
		in := &api.PolicyGroupRef{
			Id:      "group-1",
			Version: 3,
			Location: &intoto.ResourceDescriptor{
				Uri:    "git+https://example.com/x/y@abc#g.json",
				Digest: map[string]string{"sha256": "aaa"},
			},
		}
		out := groupRefToPolicyRef(in)
		require.NotNil(t, out)
		require.Equal(t, "group-1", out.GetId())
		require.EqualValues(t, 3, out.GetVersion())
		require.Equal(t, in.GetLocation().GetUri(), out.GetLocation().GetUri())
		require.Equal(t, "aaa", out.GetLocation().GetDigest()["sha256"])
	})
}

func TestCloneRef(t *testing.T) {
	t.Parallel()
	orig := &api.PolicyRef{
		Id: "ref-1",
		Location: &intoto.ResourceDescriptor{
			Uri:    "git+https://example.com/x/y@abc#p.json",
			Digest: map[string]string{"sha256": "aaa"},
		},
	}
	cp := cloneRef(orig)
	require.NotSame(t, orig, cp)
	require.Equal(t, orig.GetId(), cp.GetId())
	require.Equal(t, orig.GetLocation().GetUri(), cp.GetLocation().GetUri())

	// Mutating the clone does not alter the source.
	cp.Location.Uri = "mutated"
	cp.Location.Digest["sha256"] = "bbb"
	require.Equal(t, "git+https://example.com/x/y@abc#p.json", orig.GetLocation().GetUri())
	require.Equal(t, "aaa", orig.GetLocation().GetDigest()["sha256"])
}

func TestIsPolicyFile(t *testing.T) {
	t.Parallel()
	parser := NewParser()

	t.Run("valid-policy-fixture", func(t *testing.T) {
		t.Parallel()
		require.True(t, isPolicyFile("testdata/policy.single.json", parser))
	})

	t.Run("valid-policyset-fixture", func(t *testing.T) {
		t.Parallel()
		require.True(t, isPolicyFile("testdata/policy.remoteref.json", parser))
	})

	t.Run("missing-file", func(t *testing.T) {
		t.Parallel()
		require.False(t, isPolicyFile("testdata/does-not-exist.json", parser))
	})

	t.Run("non-policy-json", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		p := filepath.Join(dir, "junk.json")
		require.NoError(t, os.WriteFile(p, []byte(`{"random":"object"}`), 0o600))
		require.False(t, isPolicyFile(p, parser))
	})
}

func TestWalkForPolicyFiles(t *testing.T) {
	t.Parallel()
	parser := NewParser()

	root := t.TempDir()

	// Valid policy file.
	require.NoError(t, copyFile("testdata/policy.single.json", filepath.Join(root, "a.json")))
	// Policy set with a remote ref.
	require.NoError(t, copyFile("testdata/policy.remoteref.json", filepath.Join(root, "b.json")))
	// Junk file that is not a policy.
	require.NoError(t, os.WriteFile(filepath.Join(root, "junk.json"), []byte(`{"x":1}`), 0o600))
	// File with an unsupported extension is skipped even if content is a policy.
	require.NoError(t, copyFile("testdata/policy.single.json", filepath.Join(root, "c.txt")))
	// Hidden directory — its contents are skipped.
	hidden := filepath.Join(root, ".hidden")
	require.NoError(t, os.Mkdir(hidden, 0o750))
	require.NoError(t, copyFile("testdata/policy.single.json", filepath.Join(hidden, "h.json")))

	found, err := walkForPolicyFiles(root, parser)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{
		filepath.Join(root, "a.json"),
		filepath.Join(root, "b.json"),
	}, found)
}

func TestExtractAllRefs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	a := filepath.Join(root, "policy.remoteref.json")
	b := filepath.Join(root, "group.remoteref.json")
	c := filepath.Join(root, "policy.single.json") // no refs
	require.NoError(t, copyFile("testdata/policy.remoteref.json", a))
	require.NoError(t, copyFile("testdata/group.remoteref.json", b))
	require.NoError(t, copyFile("testdata/policy.single.json", c))

	u := NewUpdater()
	refs := u.extractAllRefs([]string{a, b, c})

	require.Len(t, refs, 2)

	byFile := map[string]*extractedRef{}
	for _, r := range refs {
		byFile[r.file] = r
	}

	require.Contains(t, byFile, a)
	require.Contains(t, byFile, b)

	// PolicySet → Policy source ref.
	aRef := byFile[a]
	require.NotNil(t, aRef.components)
	require.Equal(t, "github.com", aRef.components.Hostname)
	require.Equal(t, "/carabiner-dev/policies", aRef.components.RepoPath)
	require.Equal(t, "9a70ca49804c2b993bb6b62d51d5524f3443d6ec", aRef.components.Commit)
	require.Equal(t, "sbom/sbom-exists.json", aRef.components.SubPath)

	// PolicySet → PolicyGroup source ref (projected through groupRefToPolicyRef).
	bRef := byFile[b]
	require.NotNil(t, bRef.components)
	require.Equal(t, "/carabiner-dev/examples", bRef.components.RepoPath)
	require.Equal(t, "4c4ecf69b9c550fb2d57308f210a5de34802e8fb", bRef.components.Commit)
}

func TestCollectSourcesNoPolicies(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "junk.json"), []byte(`{"x":1}`), 0o600))

	u := NewUpdater()
	files, cleanup, err := u.collectSources([]string{dir})
	defer cleanup()
	require.NoError(t, err)
	require.Empty(t, files)
}

func TestCollectSourcesFileAndDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	require.NoError(t, copyFile("testdata/policy.single.json", a))

	// A second directory containing one policy.
	dir2 := t.TempDir()
	b := filepath.Join(dir2, "b.json")
	require.NoError(t, copyFile("testdata/policy.remoteref.json", b))

	u := NewUpdater()
	files, cleanup, err := u.collectSources([]string{a, dir2})
	defer cleanup()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{a, b}, files)
}

func TestCollectSourcesUnknownLocation(t *testing.T) {
	t.Parallel()
	u := NewUpdater()
	_, cleanup, err := u.collectSources([]string{"/definitely/does/not/exist"})
	defer cleanup()
	require.Error(t, err)
}

func TestCheckUpdatesNoLocations(t *testing.T) {
	t.Parallel()
	_, err := NewUpdater().CheckUpdates()
	require.Error(t, err)
}

func TestCheckUpdatesNoPoliciesFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "junk.json"), []byte(`{"x":1}`), 0o600))
	_, err := NewUpdater().CheckUpdates(dir)
	require.Error(t, err)
}

func TestCheckUpdatesNoExternalRefs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, copyFile("testdata/policy.single.json", filepath.Join(dir, "p.json")))
	// policy.single.json has no external refs, so no remote operations happen.
	updates, err := NewUpdater().CheckUpdates(dir)
	require.NoError(t, err)
	require.Empty(t, updates)
}

func TestApplyRefUpdatesReplacesURIAndDigest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "policy.json")
	const oldURI = "git+https://example.com/org/repo@deadbeef#p.json"
	const newURI = "git+https://example.com/org/repo@cafef00d#p.json"
	const oldDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const newDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	content := `{
  "policies": [
    {
      "source": {
        "location": {
          "uri": "` + oldURI + `",
          "digest": { "sha256": "` + oldDigest + `" }
        }
      }
    }
  ]
}
`
	require.NoError(t, os.WriteFile(src, []byte(content), 0o600))

	refs := []*RefUpdate{
		{
			Old: &api.PolicyRef{Location: &intoto.ResourceDescriptor{
				Uri:    oldURI,
				Digest: map[string]string{"sha256": oldDigest},
			}},
			New: &api.PolicyRef{Location: &intoto.ResourceDescriptor{
				Uri:    newURI,
				Digest: map[string]string{"sha256": newDigest},
			}},
		},
	}

	applied, err := applyRefUpdates(src, refs)
	require.NoError(t, err)
	require.Len(t, applied, 1)

	patched, err := os.ReadFile(src)
	require.NoError(t, err)
	patchedStr := string(patched)
	require.Contains(t, patchedStr, newURI)
	require.Contains(t, patchedStr, newDigest)
	require.NotContains(t, patchedStr, oldURI)
	require.NotContains(t, patchedStr, oldDigest)

	// Minimal-diff guarantee: only the two changed strings should differ
	// from the original content.
	expected := strings.ReplaceAll(content, oldURI, newURI)
	expected = strings.ReplaceAll(expected, oldDigest, newDigest)
	require.Equal(t, expected, patchedStr)
}

func TestApplyRefUpdatesNoMatchLeavesFileUnchanged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "policy.json")
	original := []byte(`{"id":"x"}`)
	require.NoError(t, os.WriteFile(src, original, 0o600))

	refs := []*RefUpdate{
		{
			Old: &api.PolicyRef{Location: &intoto.ResourceDescriptor{
				Uri: "git+https://example.com/org/repo@deadbeef#p.json",
			}},
			New: &api.PolicyRef{Location: &intoto.ResourceDescriptor{
				Uri: "git+https://example.com/org/repo@cafef00d#p.json",
			}},
		},
	}

	applied, err := applyRefUpdates(src, refs)
	require.NoError(t, err)
	require.Empty(t, applied)

	got, err := os.ReadFile(src)
	require.NoError(t, err)
	require.Equal(t, original, got)
}

func TestApplyRefUpdatesPreservesFileMode(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permission bits do not round-trip through os.WriteFile/os.Stat on Windows")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "policy.json")
	const oldURI = "git+https://example.com/org/repo@deadbeef#p.json"
	const newURI = "git+https://example.com/org/repo@cafef00d#p.json"
	require.NoError(t, os.WriteFile(src, []byte(oldURI), 0o640)) //nolint:gosec // intentional: test verifies applyRefUpdates preserves this exact mode

	refs := []*RefUpdate{
		{
			Old: &api.PolicyRef{Location: &intoto.ResourceDescriptor{Uri: oldURI}},
			New: &api.PolicyRef{Location: &intoto.ResourceDescriptor{Uri: newURI}},
		},
	}

	_, err := applyRefUpdates(src, refs)
	require.NoError(t, err)

	info, err := os.Stat(src)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o640), info.Mode().Perm())
}

func TestApplyRefUpdatesSkipsNilLocations(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "policy.json")
	const body = `{"id":"x"}`
	require.NoError(t, os.WriteFile(src, []byte(body), 0o600))

	refs := []*RefUpdate{
		{Old: &api.PolicyRef{}, New: &api.PolicyRef{}},
	}
	applied, err := applyRefUpdates(src, refs)
	require.NoError(t, err)
	require.Empty(t, applied)

	got, err := os.ReadFile(src)
	require.NoError(t, err)
	require.JSONEq(t, body, string(got))
}

func TestApplyRefUpdatesAppliesOnlyMatchingRefs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "policy.json")
	const presentOld = "git+https://example.com/a/b@1111111#p.json"
	const presentNew = "git+https://example.com/a/b@2222222#p.json"
	const absentOld = "git+https://example.com/c/d@3333333#q.json"
	const absentNew = "git+https://example.com/c/d@4444444#q.json"
	require.NoError(t, os.WriteFile(src, []byte(presentOld), 0o600))

	refs := []*RefUpdate{
		{
			Old: &api.PolicyRef{Location: &intoto.ResourceDescriptor{Uri: presentOld}},
			New: &api.PolicyRef{Location: &intoto.ResourceDescriptor{Uri: presentNew}},
		},
		{
			Old: &api.PolicyRef{Location: &intoto.ResourceDescriptor{Uri: absentOld}},
			New: &api.PolicyRef{Location: &intoto.ResourceDescriptor{Uri: absentNew}},
		},
	}

	applied, err := applyRefUpdates(src, refs)
	require.NoError(t, err)
	require.Len(t, applied, 1)
	require.Equal(t, presentOld, applied[0].Old.GetLocation().GetUri())

	got, err := os.ReadFile(src)
	require.NoError(t, err)
	require.Equal(t, presentNew, string(got))
}

func TestUpdateNoLocations(t *testing.T) {
	t.Parallel()
	_, err := NewUpdater().Update()
	require.Error(t, err)
}

func TestUpdateNoLocalLocations(t *testing.T) {
	t.Parallel()
	_, err := NewUpdater().Update("/definitely/does/not/exist")
	require.Error(t, err)
}

func TestUpdateLocalNoExternalRefs(t *testing.T) {
	t.Parallel()
	// A policy with no external refs means CheckUpdates returns empty
	// and Update has nothing to patch — no network calls are made.
	dir := t.TempDir()
	require.NoError(t, copyFile("testdata/policy.single.json", filepath.Join(dir, "p.json")))
	applied, err := NewUpdater().Update(dir)
	require.NoError(t, err)
	require.Empty(t, applied)
}

// --- helpers ---

type vcsTC struct {
	Components vcslocator.Components
}

func vcsTestComponents(repo, sub string) *vcsTC {
	return &vcsTC{
		Components: vcslocator.Components{
			Tool:      "git",
			Transport: "https",
			Hostname:  "github.com",
			RepoPath:  repo,
			SubPath:   sub,
		},
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600) //nolint:gosec // test helper; dst is always inside t.TempDir
}
