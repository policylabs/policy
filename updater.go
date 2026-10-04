// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/carabiner-dev/hasher"
	"github.com/carabiner-dev/vcslocator"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/nozzle/throttler"
	"google.golang.org/protobuf/proto"

	api "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/policy/options"
)

// RefUpdate describes one external reference whose upstream content has
// changed. Old is the reference as it appears in the policy source; New
// is a ref pointing at the new commit with refreshed digests.
type RefUpdate struct {
	Old *api.PolicyRef
	New *api.PolicyRef
}

// Updater checks policy source files for references that have updates
// available in their upstream repositories.
type Updater struct {
	// MaxParallel caps concurrent remote operations. Defaults to 4.
	MaxParallel int
}

// NewUpdater returns a new Updater with sane defaults.
func NewUpdater() *Updater {
	return &Updater{MaxParallel: 4}
}

// CheckUpdates resolves each location (a policy file, a directory, or a
// VCS locator) into a set of policy source files, extracts their external
// references and checks each referenced repository for updates. The
// returned map is keyed by source file path and lists the references that
// need to be updated.
func (u *Updater) CheckUpdates(locations ...string) (map[string][]*RefUpdate, error) {
	if len(locations) == 0 {
		return nil, errors.New("no locations provided")
	}

	sources, cleanup, err := u.collectSources(locations)
	defer cleanup()
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, errors.New("no policy source files found")
	}

	refs := u.extractAllRefs(sources)
	if len(refs) == 0 {
		return map[string][]*RefUpdate{}, nil
	}

	parallel := u.MaxParallel
	if parallel <= 0 {
		parallel = 4
	}

	type repoKey struct {
		url, refName string
	}
	heads := map[repoKey]string{}
	var hmu sync.Mutex

	byRepo := map[repoKey][]*extractedRef{}
	for _, r := range refs {
		if r.components == nil {
			continue
		}
		k := repoKey{url: r.components.RepoURL(), refName: remoteRefName(r.components)}
		byRepo[k] = append(byRepo[k], r)
	}

	// 1) Resolve latest commit per unique (repo, ref) in parallel.
	t := throttler.New(parallel, len(byRepo))
	var headErr error
	var hErrMu sync.Mutex
	for k := range byRepo {
		go func(k repoKey) {
			h, err := lsRemoteHead(k.url, k.refName)
			if err != nil {
				hErrMu.Lock()
				if headErr == nil {
					headErr = fmt.Errorf("ls-remote %s: %w", k.url, err)
				}
				hErrMu.Unlock()
				t.Done(nil)
				return
			}
			hmu.Lock()
			heads[k] = h
			hmu.Unlock()
			t.Done(nil)
		}(k)
		t.Throttle()
	}
	if headErr != nil {
		return nil, headErr
	}

	// 2) For each ref with a changed head, fetch the file at old and new
	//    and compare digests.
	results := map[string][]*RefUpdate{}
	var rmu sync.Mutex

	// Cache fetched file bytes by locator-at-commit string.
	byteCache := map[string][]byte{}
	var bmu sync.Mutex
	fetchBytes := func(locator string) ([]byte, error) {
		bmu.Lock()
		if b, ok := byteCache[locator]; ok {
			bmu.Unlock()
			return b, nil
		}
		bmu.Unlock()
		var buf bytes.Buffer
		if err := vcslocator.CopyFile(locator, &buf); err != nil {
			return nil, err
		}
		data := buf.Bytes()
		bmu.Lock()
		byteCache[locator] = data
		bmu.Unlock()
		return data, nil
	}

	t2 := throttler.New(parallel, len(refs))
	for _, r := range refs {
		go func(r *extractedRef) {
			defer t2.Done(nil)
			if r.components == nil {
				return
			}
			k := repoKey{url: r.components.RepoURL(), refName: remoteRefName(r.components)}
			hmu.Lock()
			newCommit := heads[k]
			hmu.Unlock()
			oldCommit := r.components.Commit
			if newCommit == "" || newCommit == oldCommit {
				return
			}

			newLocator := buildLocatorAt(r.components, newCommit)
			newBytes, err := fetchBytes(newLocator)
			if err != nil {
				return
			}

			oldDigests := map[string]string{}
			if loc := r.original.GetLocation(); loc != nil {
				for k, v := range loc.GetDigest() {
					oldDigests[k] = v
				}
			}

			// If the old ref had no recorded digest we need to fetch the
			// old bytes to know whether content actually changed.
			if _, haveSha256 := oldDigests["sha256"]; !haveSha256 && oldCommit != "" {
				oldLocator := buildLocatorAt(r.components, oldCommit)
				oldBytes, err := fetchBytes(oldLocator)
				if err != nil {
					return
				}
				oldHashed, err := hashBytes(oldBytes, []string{string(intoto.AlgorithmSHA256)})
				if err != nil {
					return
				}
				for k, v := range oldHashed {
					oldDigests[k] = v
				}
			}

			newDigests, err := computeDigests(newBytes, oldDigests)
			if err != nil {
				return
			}
			if newCommit != "" {
				newDigests[string(intoto.AlgorithmGitCommit)] = newCommit
			}

			if digestsMatch(oldDigests, newDigests) {
				return
			}

			newRef := cloneRef(r.original)
			if newRef.Location == nil {
				newRef.Location = &intoto.ResourceDescriptor{}
			}
			newRef.Location.Uri = newLocator
			newRef.Location.DownloadLocation = ""
			newRef.Location.Digest = newDigests

			rmu.Lock()
			results[r.file] = append(results[r.file], &RefUpdate{
				Old: r.original,
				New: newRef,
			})
			rmu.Unlock()
		}(r)
		t2.Throttle()
	}

	return results, nil
}

// Update checks the given locations for available reference updates and
// patches the matching policy source files in place. Only filesystem
// locations (files or directories) are patched; VCS-locator locations
// are skipped because their resolved files live in a temporary clone.
// The returned map lists the updates that were actually applied, keyed
// by source file path.
func (u *Updater) Update(locations ...string) (map[string][]*RefUpdate, error) {
	if len(locations) == 0 {
		return nil, errors.New("no locations provided")
	}

	local := make([]string, 0, len(locations))
	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			local = append(local, loc)
		}
	}
	if len(local) == 0 {
		return nil, errors.New("no local locations to update (remote locations are not supported by Update)")
	}

	updates, err := u.CheckUpdates(local...)
	if err != nil {
		return nil, err
	}
	return u.ApplyUpdates(updates)
}

// ApplyUpdates patches each file in the given updates map in place, using
// the same backend as Update. This is the method to call when the updates
// were computed elsewhere (e.g. loaded from a previously-saved plan) and
// only the filesystem patch step needs to run. Returns the subset of
// updates that were actually applied (i.e. whose old values were present
// in their source file).
func (u *Updater) ApplyUpdates(updates map[string][]*RefUpdate) (map[string][]*RefUpdate, error) {
	applied := map[string][]*RefUpdate{}
	for file, refs := range updates {
		patched, err := applyRefUpdates(file, refs)
		if err != nil {
			return applied, fmt.Errorf("patching %s: %w", file, err)
		}
		if len(patched) > 0 {
			applied[file] = patched
		}
	}
	return applied, nil
}

// applyRefUpdates rewrites file in place, replacing every old
// URI/DownloadLocation/digest value with its new counterpart. The
// replacements are done as raw string substitutions so that the file's
// formatting, comments, and non-policy content are preserved verbatim.
// Returns the list of updates whose values were actually present in the
// file.
func applyRefUpdates(file string, refs []*RefUpdate) ([]*RefUpdate, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	out := string(data)
	applied := []*RefUpdate{}
	for _, r := range refs {
		mutated := false
		oldLoc := r.Old.GetLocation()
		newLoc := r.New.GetLocation()
		if oldLoc == nil || newLoc == nil {
			continue
		}

		if ov, nv := oldLoc.GetUri(), newLoc.GetUri(); ov != "" && ov != nv && strings.Contains(out, ov) {
			out = strings.ReplaceAll(out, ov, nv)
			mutated = true
		}
		if ov, nv := oldLoc.GetDownloadLocation(), newLoc.GetDownloadLocation(); ov != "" && ov != nv && strings.Contains(out, ov) {
			out = strings.ReplaceAll(out, ov, nv)
			mutated = true
		}
		for algo, ov := range oldLoc.GetDigest() {
			nv, ok := newLoc.GetDigest()[algo]
			if !ok || ov == "" || ov == nv {
				continue
			}
			if !strings.Contains(out, ov) {
				continue
			}
			out = strings.ReplaceAll(out, ov, nv)
			mutated = true
		}
		if mutated {
			applied = append(applied, r)
		}
	}

	if len(applied) == 0 {
		return applied, nil
	}
	if err := os.WriteFile(file, []byte(out), info.Mode().Perm()); err != nil { //nolint:gosec // file is the policy source we just read; mode is preserved from its existing stat
		return applied, err
	}
	return applied, nil
}

// extractedRef is the internal working copy of a reference under review.
type extractedRef struct {
	file       string
	original   *api.PolicyRef
	components *vcslocator.Components
}

// collectSources turns each input location into a slice of local policy
// file paths. For VCS-locator inputs it clones the repository to a temp
// directory and treats the result as a filesystem input.
func (u *Updater) collectSources(locations []string) (files []string, cleanup func(), err error) {
	var tmpDirs []string
	cleanup = func() {
		for _, d := range tmpDirs {
			if rerr := os.RemoveAll(d); rerr != nil {
				err = errors.Join(err, fmt.Errorf("removing temp dir %q: %w", d, rerr))
			}
		}
	}

	parser := NewParser()
	for _, loc := range locations {
		if info, err := os.Stat(loc); err == nil {
			if info.IsDir() {
				found, err := walkForPolicyFiles(loc, parser)
				if err != nil {
					return nil, cleanup, err
				}
				files = append(files, found...)
			} else if isPolicyFile(loc, parser) {
				files = append(files, loc)
			}
			continue
		}

		// Not on the filesystem; try as a VCS locator.
		l := vcslocator.Locator(loc)
		comps, err := l.Parse()
		if err != nil || comps.Tool != "git" {
			return nil, cleanup, fmt.Errorf("location %q is not a file, directory, or valid VCS locator", loc)
		}

		tmp, err := os.MkdirTemp("", "policyctl-checkupdate-")
		if err != nil {
			return nil, cleanup, fmt.Errorf("creating temp dir: %w", err)
		}
		tmpDirs = append(tmpDirs, tmp)

		if _, err := vcslocator.CloneRepository(loc, vcslocator.WithClonePath(tmp)); err != nil {
			return nil, cleanup, fmt.Errorf("cloning %q: %w", loc, err)
		}

		target := tmp
		if comps.SubPath != "" {
			target = filepath.Join(tmp, comps.SubPath)
		}
		info, err := os.Stat(target)
		if err != nil {
			return nil, cleanup, fmt.Errorf("resolving subpath %q: %w", comps.SubPath, err)
		}
		if info.IsDir() {
			found, err := walkForPolicyFiles(target, parser)
			if err != nil {
				return nil, cleanup, err
			}
			files = append(files, found...)
		} else if isPolicyFile(target, parser) {
			files = append(files, target)
		}
	}

	return files, cleanup, nil
}

func walkForPolicyFiles(root string, parser *Parser) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".json" && ext != ".hjson" && ext != ".ampel" {
			return nil
		}
		if isPolicyFile(p, parser) {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

func isPolicyFile(path string, parser *Parser) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	set, pcy, grp, _, err := parser.ParseVerifyPolicyOrSetOrGroup(data, options.WithVerifySignatures(false))
	if err != nil {
		return false
	}
	return set != nil || pcy != nil || grp != nil
}

// extractAllRefs parses each source file and collects external references.
func (u *Updater) extractAllRefs(files []string) []*extractedRef {
	var refs []*extractedRef
	parser := NewParser()
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		set, pcy, grp, _, err := parser.ParseVerifyPolicyOrSetOrGroup(data, options.WithVerifySignatures(false))
		if err != nil {
			continue
		}

		add := func(ref *api.PolicyRef) {
			if ref == nil || ref.GetLocation() == nil {
				return
			}
			uri := ref.GetSourceURL()
			if uri == "" {
				return
			}
			comps, cerr := vcslocator.Locator(uri).Parse()
			if cerr != nil {
				return
			}
			refs = append(refs, &extractedRef{
				file:       path,
				original:   ref,
				components: comps,
			})
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
				add(groupRefToPolicyRef(g.GetSource()))
				for _, b := range g.GetBlocks() {
					for _, p := range b.GetPolicies() {
						add(p.GetSource())
					}
				}
			}
		case pcy != nil:
			add(pcy.GetSource())
		case grp != nil:
			add(groupRefToPolicyRef(grp.GetSource()))
			for _, b := range grp.GetBlocks() {
				for _, p := range b.GetPolicies() {
					add(p.GetSource())
				}
			}
		}
	}
	return refs
}

// groupRefToPolicyRef projects a PolicyGroupRef into the shape of a
// PolicyRef so both can flow through the same update pipeline.
func groupRefToPolicyRef(g *api.PolicyGroupRef) *api.PolicyRef {
	if g == nil {
		return nil
	}
	return &api.PolicyRef{
		Id:       g.GetId(),
		Version:  g.GetVersion(),
		Identity: g.GetIdentity(),
		Location: g.GetLocation(),
	}
}

func cloneRef(r *api.PolicyRef) *api.PolicyRef {
	cp, ok := proto.Clone(r).(*api.PolicyRef)
	if !ok {
		return &api.PolicyRef{}
	}
	return cp
}

// hashBytes hashes `data` using the given algorithm names. Algorithms not
// supported by the hasher package are skipped.
func hashBytes(data []byte, algos []string) (map[string]string, error) {
	filtered := []intoto.HashAlgorithm{}
	for _, a := range algos {
		algo := intoto.HashAlgorithm(a)
		if _, ok := hasher.HasherFactory[algo]; ok {
			filtered = append(filtered, algo)
		}
	}
	if len(filtered) == 0 {
		return map[string]string{}, nil
	}
	h := hasher.New()
	h.Options.Algorithms = filtered
	list, err := h.HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil {
		return nil, fmt.Errorf("hashing: %w", err)
	}
	if list == nil || len(*list) == 0 {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	for algo, digest := range (*list)[0] {
		out[string(algo)] = digest
	}
	return out, nil
}

// computeDigests produces digests for `data` covering every algorithm
// present in `reference` plus sha256 as a guaranteed default.
func computeDigests(data []byte, reference map[string]string) (map[string]string, error) {
	seen := map[string]struct{}{string(intoto.AlgorithmSHA256): {}}
	algos := []string{string(intoto.AlgorithmSHA256)}
	for k := range reference {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		algos = append(algos, k)
	}
	return hashBytes(data, algos)
}

// digestsMatch reports whether newDigests is consistent with oldDigests.
// Every algorithm in newDigests must either match the corresponding entry
// in oldDigests or have no corresponding entry at all. At least one
// algorithm must overlap between the two maps — if none do, the result
// is false.
func digestsMatch(oldDigests, newDigests map[string]string) bool {
	overlap := 0
	for algo, nv := range newDigests {
		ov, ok := oldDigests[algo]
		if !ok {
			continue
		}
		if ov != nv {
			return false
		}
		overlap++
	}
	return overlap > 0
}

// lsRemoteHead queries the remote for the latest commit of refName. If
// refName is empty, HEAD is resolved.
func lsRemoteHead(repoURL, refName string) (string, error) {
	rem := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{repoURL},
	})
	refs, err := rem.List(&git.ListOptions{})
	if err != nil {
		return "", err
	}

	if refName == "" {
		for _, r := range refs {
			if r.Name() == plumbing.HEAD && r.Type() == plumbing.SymbolicReference {
				refName = r.Target().String()
				break
			}
		}
	}

	for _, r := range refs {
		if r.Name().String() == refName {
			return r.Hash().String(), nil
		}
	}
	for _, r := range refs {
		if r.Name() == plumbing.HEAD && r.Type() == plumbing.HashReference {
			return r.Hash().String(), nil
		}
	}
	return "", fmt.Errorf("ref %q not found in remote", refName)
}

// remoteRefName converts the parsed locator into a remote ref name. Empty
// means "HEAD/default branch".
func remoteRefName(c *vcslocator.Components) string {
	switch {
	case c.Branch != "":
		return "refs/heads/" + c.Branch
	case c.Tag != "":
		return "refs/tags/" + c.Tag
	default:
		return ""
	}
}

// buildLocatorAt rewrites a locator to point at a specific commit while
// preserving the subpath.
func buildLocatorAt(c *vcslocator.Components, commit string) string {
	repo := strings.TrimPrefix(c.RepoPath, "/")
	var b strings.Builder
	fmt.Fprintf(&b, "git+%s://%s/%s@%s", c.Transport, c.Hostname, repo, commit)
	if c.SubPath != "" {
		fmt.Fprintf(&b, "#%s", c.SubPath)
	}
	return b.String()
}
