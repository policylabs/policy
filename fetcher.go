// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/carabiner-dev/vcslocator"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"sigs.k8s.io/release-utils/http"

	"github.com/policylabs/policy/options"
)

// SchemeFetcher turns the policy locations of one family, named by their
// scheme, into the bytes stored there: bare JSON, a DSSE envelope or a
// sigstore bundle. The compiler parses and verifies whatever comes back; a
// fetcher only moves bytes. The default ones handle http(s) URLs and git
// VCS locators; a caller registers more on the Fetcher (see WithFetcher),
// so a store the compiler knows nothing about, such as an attestation
// store that also holds policies, is one more fetcher rather than a
// change here.
type SchemeFetcher interface {
	// Supports reports whether this fetcher handles the location. It decides
	// by scheme and never touches the network.
	Supports(location string) bool
	// Get fetches one location.
	Get(ctx context.Context, location string) ([]byte, error)
	// GetGroup fetches a batch the fetcher may optimize together (one clone
	// per repository, parallel requests), preserving the order given. A
	// fetcher with nothing to share across locations may call Get in a loop.
	GetGroup(ctx context.Context, locations []string) ([][]byte, error)
}

// SelfResolver is implemented by a SchemeFetcher whose locations name a
// file in a repository at a revision, which is what a self reference (a
// "$/" reference, see api.SelfReferencePrefix) is resolved against: the
// repository and the revision of the document it is written in. A fetcher
// of plain URLs has neither and does not implement it.
type SelfResolver interface {
	// PinLocation returns the location with its revision fixed: one that
	// names a branch, a tag or no revision at all comes back naming the
	// commit it points to now, one that is pinned comes back as it is.
	PinLocation(ctx context.Context, location string) (string, error)
	// ResolveSelf returns the location of the file at path, counted from
	// the root of the repository, in the repository and at the revision
	// of base. It refuses a base that is not pinned.
	ResolveSelf(base, path string) (string, error)
}

// ErrSelfReferenceUnsupported is returned when a self reference is written
// in a document read from a location that is not in a repository, such as
// an HTTP URL: there is no revision the reference could be read at.
var ErrSelfReferenceUnsupported = errors.New(
	"self references are not supported in documents read from this kind of location",
)

// Fetcher is the ampel policy fetcher: it dispatches each location to the
// first registered SchemeFetcher that supports it, fetches a group's
// families concurrently, and enforces the size limits.
type Fetcher struct {
	Limits   options.Limits
	fetchers []SchemeFetcher
}

// NewFetcher returns a fetcher with the default limits and the default
// scheme fetchers: HTTPFetcher and VCSFetcher.
func NewFetcher() *Fetcher {
	return NewFetcherWithLimits(options.DefaultLimits)
}

// NewFetcherWithLimits creates a new Fetcher with the specified limits and
// the default scheme fetchers.
func NewFetcherWithLimits(limits options.Limits) *Fetcher {
	return &Fetcher{
		Limits: limits,
		fetchers: []SchemeFetcher{
			&HTTPFetcher{MaxInputSize: limits.MaxInputSize},
			&VCSFetcher{MaxInputSize: limits.MaxInputSize},
		},
	}
}

// Register adds a scheme fetcher. Fetchers are asked in registration order,
// so one registered later never shadows the defaults for the schemes they
// handle.
func (gf *Fetcher) Register(fetchers ...SchemeFetcher) {
	gf.fetchers = append(gf.fetchers, fetchers...)
}

// Supports reports whether any registered fetcher handles the location.
func (gf *Fetcher) Supports(location string) bool {
	return gf.fetcherFor(location) != nil
}

// PinLocation fixes the revision of a location when the fetcher handling
// it knows of revisions (see SelfResolver). Any other location is returned
// as it is.
func (gf *Fetcher) PinLocation(ctx context.Context, location string) (string, error) {
	if sr, ok := gf.fetcherFor(location).(SelfResolver); ok {
		return sr.PinLocation(ctx, location)
	}
	return location, nil
}

// ResolveSelf returns the location a self reference to path points to when
// written in the document read from base. It returns
// ErrSelfReferenceUnsupported when base is not a location in a repository.
func (gf *Fetcher) ResolveSelf(base, path string) (string, error) {
	sr, ok := gf.fetcherFor(base).(SelfResolver)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrSelfReferenceUnsupported, base)
	}
	return sr.ResolveSelf(base, path)
}

func (gf *Fetcher) fetcherFor(location string) SchemeFetcher {
	for _, f := range gf.fetchers {
		if f.Supports(location) {
			return f
		}
	}
	return nil
}

// limitedWriter wraps a writer and enforces a maximum write size.
type limitedWriter struct {
	w       io.Writer
	max     int64
	written int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.max > 0 && lw.written+int64(len(p)) > lw.max {
		return 0, options.NewInputSizeError(lw.max, lw.written+int64(len(p)), "")
	}
	n, err := lw.w.Write(p)
	lw.written += int64(n)
	return n, err
}

// GetGroup fetches a list of locations, each handled by the fetcher that
// supports it, the families in parallel. The returned slice of byte slices
// preserves the order of the locations. If a request fails, this function
// returns an error and discards all data.
//
// Retries are currently not supported but will probably be at a later point
// once the VCS locator module supports retrying.
func (gf *Fetcher) GetGroup(ctx context.Context, locations []string) ([][]byte, error) {
	// Partition the locations by the fetcher that handles them, keeping
	// their positions.
	type batch struct {
		fetcher   SchemeFetcher
		positions []int
		locations []string
	}
	batches := []*batch{}
	byFetcher := map[SchemeFetcher]*batch{}
	for i, location := range locations {
		f := gf.fetcherFor(location)
		if f == nil {
			return nil, fmt.Errorf("unable to handle referenced URI %q: no fetcher supports it", location)
		}
		b, ok := byFetcher[f]
		if !ok {
			b = &batch{fetcher: f}
			byFetcher[f] = b
			batches = append(batches, b)
		}
		b.positions = append(b.positions, i)
		b.locations = append(b.locations, location)
	}

	// Preallocate the return slice to populate later
	ret := make([][]byte, len(locations))
	errs := make([]error, len(batches))
	var mtx sync.Mutex
	var wg sync.WaitGroup
	for i, b := range batches {
		wg.Add(1)
		go func(i int, b *batch) {
			defer wg.Done()
			res, err := b.fetcher.GetGroup(ctx, b.locations)
			if err != nil {
				errs[i] = err
				return
			}
			if len(res) != len(b.locations) {
				errs[i] = fmt.Errorf("fetcher %T answered %d documents for %d locations", b.fetcher, len(res), len(b.locations))
				return
			}
			mtx.Lock()
			for j, data := range res {
				ret[b.positions[j]] = data
			}
			mtx.Unlock()
		}(i, b)
	}
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	// Check size limits on fetched data
	maxSize := gf.Limits.MaxInputSize
	if maxSize > 0 {
		for i, data := range ret {
			if int64(len(data)) > maxSize {
				return nil, options.NewInputSizeError(maxSize, int64(len(data)), locations[i]) //nolint:gosec // ret was made the length of locations
			}
		}
	}

	return ret, nil
}

// GetGroupBatched fetches locations in batches to limit parallel connections.
// This is useful for preventing connection exhaustion when fetching many resources.
func (gf *Fetcher) GetGroupBatched(ctx context.Context, locations []string, batchSize int) ([][]byte, error) {
	if batchSize <= 0 {
		batchSize = gf.Limits.MaxParallelFetches
	}
	if batchSize <= 0 {
		batchSize = options.DefaultMaxParallelFetches
	}

	results := make([][]byte, len(locations))

	// Process in batches
	for i := 0; i < len(locations); i += batchSize {
		end := min(i+batchSize, len(locations))

		batch := locations[i:end]
		batchResults, err := gf.GetGroup(ctx, batch)
		if err != nil {
			return nil, fmt.Errorf("fetching batch starting at index %d: %w", i, err)
		}

		// Copy batch results to the appropriate positions
		for j, data := range batchResults {
			results[i+j] = data
		}
	}

	return results, nil
}

// Get fetches one location through the fetcher that supports it.
func (gf *Fetcher) Get(ctx context.Context, location string) ([]byte, error) {
	f := gf.fetcherFor(location)
	if f == nil {
		return nil, fmt.Errorf("unable to handle referenced URI %q: no fetcher supports it", location)
	}
	data, err := f.Get(ctx, location)
	if err != nil {
		return nil, err
	}
	if maxSize := gf.Limits.MaxInputSize; maxSize > 0 && int64(len(data)) > maxSize {
		return nil, options.NewInputSizeError(maxSize, int64(len(data)), location)
	}
	return data, nil
}

// HTTPFetcher fetches http:// and https:// URLs with the release-utils
// agent.
type HTTPFetcher struct {
	// MaxInputSize bounds one response; zero means no limit.
	MaxInputSize int64
}

// Supports implements SchemeFetcher.
func (hf *HTTPFetcher) Supports(location string) bool {
	return strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://")
}

// Get retrieves data from an http endpoint with size limits.
func (hf *HTTPFetcher) Get(_ context.Context, url string) ([]byte, error) {
	if hf.MaxInputSize <= 0 {
		// No limit, use the standard agent
		return http.NewAgent().Get(url)
	}

	// Use limited writer to enforce size limit
	var b bytes.Buffer
	lw := &limitedWriter{w: &b, max: hf.MaxInputSize}
	if err := http.NewAgent().GetToWriter(lw, url); err != nil {
		return nil, fmt.Errorf("fetching URL: %w", err)
	}

	return b.Bytes(), nil
}

// GetGroup fetches the URLs in parallel.
func (hf *HTTPFetcher) GetGroup(_ context.Context, urls []string) ([][]byte, error) {
	res, errs := http.NewAgent().GetGroup(urls)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return res, nil
}

// VCSFetcher fetches git+ VCS locators (git+https, git+ssh, git+file) with
// the vcslocator module, with its defaults (system credentials, no clone
// path); the module does not export its option type yet.
type VCSFetcher struct {
	// MaxInputSize bounds one file; zero means no limit.
	MaxInputSize int64
}

// Supports implements SchemeFetcher.
func (vf *VCSFetcher) Supports(location string) bool {
	return strings.HasPrefix(location, "git+")
}

// Get gets data from a git repository at the specified revision with size limits.
func (vf *VCSFetcher) Get(_ context.Context, locator string) ([]byte, error) {
	var b bytes.Buffer
	if vf.MaxInputSize <= 0 {
		// No limit
		if err := vcslocator.CopyFile(locator, &b); err != nil {
			return nil, fmt.Errorf("fetching data from git: %w", err)
		}
		return b.Bytes(), nil
	}

	// Use limited writer to enforce size limit
	lw := &limitedWriter{w: &b, max: vf.MaxInputSize}
	if err := vcslocator.CopyFile(locator, lw); err != nil {
		return nil, fmt.Errorf("fetching data from git: %w", err)
	}
	return b.Bytes(), nil
}

// GetGroup fetches the locators, cloning each repository once.
func (vf *VCSFetcher) GetGroup(_ context.Context, locators []string) ([][]byte, error) {
	return vcslocator.GetGroup(locators)
}

var _ SelfResolver = (*VCSFetcher)(nil)

// PinLocation implements SelfResolver. A locator that names no commit is
// resolved by asking the remote what its branch or tag, or its default
// branch when it names neither, points to.
func (vf *VCSFetcher) PinLocation(ctx context.Context, locator string) (string, error) {
	comps, err := vcslocator.Locator(locator).Parse()
	if err != nil {
		return "", fmt.Errorf("parsing VCS locator: %w", err)
	}
	if comps.Commit != "" {
		return locator, nil
	}

	commit, err := resolveRemoteCommit(ctx, locator, comps)
	if err != nil {
		return "", fmt.Errorf("resolving the commit of %q: %w", locator, err)
	}
	return vcsLocatorAt(comps, commit, comps.SubPath), nil
}

// ResolveSelf implements SelfResolver.
func (vf *VCSFetcher) ResolveSelf(base, path string) (string, error) {
	comps, err := vcslocator.Locator(base).Parse()
	if err != nil {
		return "", fmt.Errorf("parsing VCS locator: %w", err)
	}
	if !fullCommitRegex.MatchString(comps.Commit) {
		return "", fmt.Errorf("unable to resolve a self reference against %q: it does not name a full commit", base)
	}
	return vcsLocatorAt(comps, comps.Commit, path), nil
}

// fullCommitRegex matches the full name of a commit, SHA-1 or SHA-256.
var fullCommitRegex = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// vcsLocatorAt builds the locator of a path of a repository at a commit.
func vcsLocatorAt(c *vcslocator.Components, commit, subPath string) string {
	repo := strings.TrimPrefix(c.RepoPath, "/")
	var b strings.Builder
	fmt.Fprintf(&b, "git+%s://%s/%s@%s", c.Transport, c.Hostname, repo, commit)
	if subPath != "" {
		fmt.Fprintf(&b, "#%s", subPath)
	}
	return b.String()
}

// resolveRemoteCommit asks the remote of a locator for the commit its
// revision points to. A revision written as a bare name is looked up as a
// tag and then as a branch; no revision means the default branch.
func resolveRemoteCommit(ctx context.Context, locator string, c *vcslocator.Components) (string, error) {
	auth, err := vcslocator.GetAuthMethod(locator)
	if err != nil {
		return "", fmt.Errorf("getting credentials: %w", err)
	}

	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{c.RepoURL()},
	})
	// Annotated tags are listed twice: under their name, pointing to the
	// tag object, and peeled ("name^{}"), pointing to the commit.
	refs, err := rem.ListContext(ctx, &git.ListOptions{Auth: auth, PeelingOption: git.AppendPeeled})
	if err != nil {
		return "", fmt.Errorf("listing remote references: %w", err)
	}
	hashes := map[string]string{}
	var head string
	for _, r := range refs {
		if r.Type() == plumbing.SymbolicReference {
			if r.Name() == plumbing.HEAD {
				head = r.Target().String()
			}
			continue
		}
		hashes[r.Name().String()] = r.Hash().String()
	}

	var names []string
	switch {
	case c.RefString == "":
		names = []string{head, plumbing.HEAD.String()}
	case strings.HasPrefix(c.RefString, "refs/"):
		names = []string{c.RefString}
	default:
		names = []string{"refs/tags/" + c.RefString, "refs/heads/" + c.RefString}
	}
	for _, name := range names {
		if h, ok := hashes[name+"^{}"]; ok {
			return h, nil
		}
		if h, ok := hashes[name]; ok {
			return h, nil
		}
	}
	if c.RefString == "" {
		return "", errors.New("the remote has no default branch")
	}
	return "", fmt.Errorf("%w: %q", vcslocator.ErrRefNotFound, c.RefString)
}
