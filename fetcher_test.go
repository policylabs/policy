// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/policy/options"
)

// memFetcher serves a scheme from memory and records how it was asked.
type memFetcher struct {
	scheme string
	docs   map[string][]byte
	groups [][]string
	err    error
}

func (m *memFetcher) Supports(location string) bool {
	return strings.HasPrefix(location, m.scheme+"://")
}

func (m *memFetcher) Get(_ context.Context, location string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	data, ok := m.docs[location]
	if !ok {
		return nil, errors.New("not found: " + location)
	}
	return data, nil
}

func (m *memFetcher) GetGroup(ctx context.Context, locations []string) ([][]byte, error) {
	m.groups = append(m.groups, locations)
	out := make([][]byte, 0, len(locations))
	for _, l := range locations {
		data, err := m.Get(ctx, l)
		if err != nil {
			return nil, err
		}
		out = append(out, data)
	}
	return out, nil
}

func TestFetcherDispatchesBySchemeInOrder(t *testing.T) {
	t.Parallel()
	one := &memFetcher{scheme: "one", docs: map[string][]byte{"one://a": []byte("a"), "one://c": []byte("c")}}
	two := &memFetcher{scheme: "two", docs: map[string][]byte{"two://b": []byte("b")}}
	f := NewFetcher()
	f.Register(one, two)

	// The defaults are still there, and the registered schemes are known.
	require.True(t, f.Supports("https://example.com/p.json"))
	require.True(t, f.Supports("git+https://github.com/org/repo#p.json"))
	require.True(t, f.Supports("one://a"))
	require.False(t, f.Supports("three://x"))
	require.False(t, f.Supports("/tmp/policy.json"))

	data, err := f.Get(t.Context(), "two://b")
	require.NoError(t, err)
	require.Equal(t, "b", string(data))

	// A group is partitioned by fetcher, each asked once, the order kept.
	res, err := f.GetGroup(t.Context(), []string{"one://a", "two://b", "one://c"})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("a"), []byte("b"), []byte("c")}, res)
	require.Equal(t, [][]string{{"one://a", "one://c"}}, one.groups)
	require.Equal(t, [][]string{{"two://b"}}, two.groups)

	// An unknown scheme fails the whole group before anything is fetched.
	_, err = f.GetGroup(t.Context(), []string{"one://a", "three://x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "three://x")
	require.Len(t, one.groups, 1)

	// A fetcher's failure is the group's.
	two.err = errors.New("down")
	_, err = f.GetGroup(t.Context(), []string{"one://a", "two://b"})
	require.ErrorIs(t, err, two.err)
}

func TestFetcherEnforcesSizeLimits(t *testing.T) {
	t.Parallel()
	big := &memFetcher{scheme: "big", docs: map[string][]byte{"big://x": []byte("0123456789")}}
	f := NewFetcherWithLimits(options.Limits{MaxInputSize: 4, MaxParallelFetches: 2})
	f.Register(big)
	_, err := f.Get(t.Context(), "big://x")
	require.Error(t, err)
	_, err = f.GetGroup(t.Context(), []string{"big://x"})
	require.Error(t, err)

	// Batching asks the fetcher in slices of the batch size.
	small := &memFetcher{scheme: "s", docs: map[string][]byte{"s://1": []byte("1"), "s://2": []byte("2"), "s://3": []byte("3")}}
	f.Register(small)
	res, err := f.GetGroupBatched(t.Context(), []string{"s://1", "s://2", "s://3"}, 0)
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte("1"), []byte("2"), []byte("3")}, res)
	require.Equal(t, [][]string{{"s://1", "s://2"}, {"s://3"}}, small.groups)
}

func TestDefaultSchemeFetchers(t *testing.T) {
	t.Parallel()
	h := &HTTPFetcher{}
	require.True(t, h.Supports("http://example.com/p"))
	require.True(t, h.Supports("https://example.com/p"))
	require.False(t, h.Supports("git+https://github.com/org/repo"))
	v := &VCSFetcher{}
	require.True(t, v.Supports("git+https://github.com/org/repo#p.json"))
	require.True(t, v.Supports("git+ssh://github.com/org/repo#p.json"))
	require.False(t, v.Supports("https://example.com/p"))
}

// A compiler with a registered scheme compiles a root location of that
// scheme and resolves the references under it through the same fetcher.
func TestCompileVerifyLocationThroughRegisteredFetcher(t *testing.T) {
	t.Parallel()
	mem := &memFetcher{scheme: "mem", docs: map[string][]byte{
		"mem://set": []byte(`{
			"id": "set-over-mem",
			"meta": {"description": "set referencing a policy over a registered scheme"},
			"policies": [{"source": {"location": {"uri": "mem://policy"}}}]
		}`),
		"mem://policy": []byte(`{
			"id": "policy-over-mem",
			"meta": {"description": "a policy served from memory"},
			"tenets": [{"id": "t1", "code": "true"}]
		}`),
	}}
	compiler := NewCompiler(WithFetcher(mem))
	set, pcy, grp, err := compiler.CompileLocation("mem://set", options.WithVerifySignatures(false))
	require.NoError(t, err)
	require.Nil(t, pcy)
	require.Nil(t, grp)
	require.NotNil(t, set)
	require.Len(t, set.GetPolicies(), 1)
	require.Equal(t, "policy-over-mem", set.GetPolicies()[0].GetId())
	require.Nil(t, set.GetPolicies()[0].GetSource(), "the reference is inlined")
	require.Equal(t, [][]string{{"mem://policy"}}, mem.groups)

	// Without the fetcher the location is unknown.
	_, _, _, err = NewCompiler().CompileLocation("mem://set", options.WithVerifySignatures(false))
	require.Error(t, err)

	// The parser opens through its fetcher too.
	parser := NewParser()
	parser.Fetcher.Register(mem)
	_, pcy, _, err = parser.Open("mem://policy", options.WithVerifySignatures(false))
	require.NoError(t, err)
	require.Equal(t, "policy-over-mem", pcy.GetId())
}
