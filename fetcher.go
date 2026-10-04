// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/carabiner-dev/vcslocator"
	"sigs.k8s.io/release-utils/http"

	"github.com/policylabs/policy/options"
)

type PolicyFetcher interface {
	Get(string) ([]byte, error)
	GetGroup(uris []string) ([][]byte, error)
}

func NewFetcher() *Fetcher {
	return &Fetcher{
		Limits: options.DefaultLimits,
	}
}

// NewFetcherWithLimits creates a new Fetcher with the specified limits.
func NewFetcherWithLimits(limits options.Limits) *Fetcher {
	return &Fetcher{
		Limits: limits,
	}
}

// Fetcher is the ampel policy fetcher. It optimizes retrieval of policy data
// from repositories and source control systems.
type Fetcher struct {
	Limits options.Limits
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

// GetGroup fetches a list of uris that can be HTTP(S) URLs or SPDX VCS locators.
// The functions uses the vcslocator module and the k8s http agent to fetch in
// parallel. The returned slice if byte-slices is guarranteed to preserve the
// URL order. If a request fails, this function returns a single error and discards
// all data.
//
// Retries are currently not supported but will probably be at a later point once
// the VCS locator module supports retrying.
func (gf *Fetcher) GetGroup(uris []string) ([][]byte, error) {
	// Split the URIs into http and vcs locators
	locators := map[int]string{}
	urls := map[int]string{}
	for i, uri := range uris {
		switch {
		case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
			urls[i] = uri
		case strings.HasPrefix(uri, "git+"):
			locators[i] = uri
		default:
			return nil, fmt.Errorf("unable to handle referenced URI %q", uri)
		}
	}

	var locatorErr error

	// Prealocate the return slice to populate later
	ret := make([][]byte, len(uris))
	errs := []error{}
	var mtx sync.Mutex
	// Create a waitgroup to fetch in parallel:
	var wg sync.WaitGroup
	wg.Add(2)

	// Fetch the VCS locators
	go func() {
		defer wg.Done()
		if len(locators) == 0 {
			return
		}
		uris := make([]string, len(locators))
		order := map[int]int{}
		i := 0
		for k, l := range locators {
			order[i] = k
			uris[i] = l
			i++
		}

		var res [][]byte
		res, locatorErr = vcslocator.GetGroup(uris)

		// If error, return early
		if locatorErr != nil {
			return
		}

		mtx.Lock()
		for i, data := range res {
			ret[order[i]] = data
		}
		mtx.Unlock()
	}()

	// Fetch the HTTP references
	go func() {
		defer wg.Done()
		if len(urls) == 0 {
			return
		}

		uris := make([]string, len(urls))
		order := map[int]int{}
		i := 0
		for k, l := range urls {
			order[i] = k
			uris[i] = l
			i++
		}

		var res [][]byte
		res, errs = http.NewAgent().GetGroup(uris)
		if errors.Join(errs...) != nil {
			return
		}

		mtx.Lock()
		for i, data := range res {
			ret[order[i]] = data
		}
		mtx.Unlock()
	}()

	// Waint until both are done
	wg.Wait()

	// Now, merge the results of both operations.
	// First the errors. The vcs locator module returns a single error
	// while the http error returns a slice, so we combine them before join.
	if locatorErr != nil {
		errs = append(errs, locatorErr)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	// Check size limits on fetched data
	maxSize := gf.Limits.MaxInputSize
	if maxSize > 0 {
		for i, data := range ret {
			if int64(len(data)) > maxSize {
				return nil, options.NewInputSizeError(maxSize, int64(len(data)), uris[i])
			}
		}
	}

	return ret, nil
}

// GetGroupBatched fetches URIs in batches to limit parallel connections.
// This is useful for preventing connection exhaustion when fetching many resources.
func (gf *Fetcher) GetGroupBatched(uris []string, batchSize int) ([][]byte, error) {
	if batchSize <= 0 {
		batchSize = gf.Limits.MaxParallelFetches
	}
	if batchSize <= 0 {
		batchSize = options.DefaultMaxParallelFetches
	}

	results := make([][]byte, len(uris))

	// Process in batches
	for i := 0; i < len(uris); i += batchSize {
		end := i + batchSize
		if end > len(uris) {
			end = len(uris)
		}

		batch := uris[i:end]
		batchResults, err := gf.GetGroup(batch)
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

func (gf *Fetcher) Get(uri string) ([]byte, error) {
	switch {
	case strings.HasPrefix(uri, "http://"), strings.HasPrefix(uri, "https://"):
		return gf.GetFromHTTP(uri)
	case strings.HasPrefix(uri, "git+"):
		return gf.GetFromGit(uri)
	default:
		return nil, fmt.Errorf("unable to handle referenced URI")
	}
}

// GetFromHTTP retrieves data from an http endpoint with size limits.
func (gf *Fetcher) GetFromHTTP(url string) ([]byte, error) {
	maxSize := gf.Limits.MaxInputSize
	if maxSize <= 0 {
		// No limit, use the standard agent
		return http.NewAgent().Get(url)
	}

	// Use limited writer to enforce size limit
	var b bytes.Buffer
	lw := &limitedWriter{w: &b, max: maxSize}
	if err := http.NewAgent().GetToWriter(lw, url); err != nil {
		return nil, fmt.Errorf("fetching URL: %w", err)
	}

	return b.Bytes(), nil
}

// GetFromGit gets data from a git repository at the specified revision with size limits.
func (gf *Fetcher) GetFromGit(locator string) ([]byte, error) {
	var b bytes.Buffer
	maxSize := gf.Limits.MaxInputSize

	if maxSize <= 0 {
		// No limit
		if err := vcslocator.CopyFile(locator, &b); err != nil {
			return nil, fmt.Errorf("fetching data from git: %w", err)
		}
		return b.Bytes(), nil
	}

	// Use limited writer to enforce size limit
	lw := &limitedWriter{w: &b, max: maxSize}
	if err := vcslocator.CopyFile(locator, lw); err != nil {
		return nil, fmt.Errorf("fetching data from git: %w", err)
	}
	return b.Bytes(), nil
}
