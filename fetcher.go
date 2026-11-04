// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/carabiner-dev/vcslocator"
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
