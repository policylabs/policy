// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/vcslocator"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/signer/key"
	"google.golang.org/protobuf/proto"
)

const (
	SigstoreModeExact  string = "exact"
	SigstoreModeRegexp string = "regexp"
)

func (meta *Meta) testsControl(ctrl *Control) bool {
	if meta.GetControls() == nil {
		return false
	}
	for _, c := range meta.GetControls() {
		if ctrl.Class == "" {
			if c.GetId() == ctrl.GetId() {
				return true
			}
		} else {
			if c.GetId() == ctrl.GetId() && c.GetClass() == ctrl.GetClass() {
				return true
			}
		}
	}
	return false
}

func (policy *Policy) TestsControl(ctrl *Control) bool {
	if ctrl == nil {
		return false
	}

	if policy.GetMeta() == nil {
		return false
	}
	return policy.GetMeta().testsControl(ctrl)
}

func (ref *PolicyRef) SetVersion(v int64) {
	ref.Version = v
}

// GetSourceURL returns the URL to fetch the policy. First, it will try the
// DownloadLocation, if empty returns the UR
func (ref *PolicyRef) GetSourceURL() string {
	if ref.GetLocation() == nil {
		return ""
	}

	if ref.GetLocation().GetDownloadLocation() != "" {
		return ref.GetLocation().GetDownloadLocation()
	}
	return ref.GetLocation().GetUri()
}

// Validate returns an error if the reference is not valid
func (ref *PolicyRef) Validate() error {
	errs := []error{}

	// If the download URL is not a VCS locator, the policy MUST have at least one hash
	if ref.GetLocation() != nil {
		uri := ref.GetLocation().GetUri()
		if uri == "" {
			uri = ref.GetLocation().GetDownloadLocation()
		}

		// Ensure a remote reference hash a hash or digest
		if len(ref.GetLocation().GetDigest()) == 0 {
			// VCS locators can have a commit or a hash
			if strings.HasPrefix(uri, "git+") {
				l := vcslocator.Locator(uri)
				parts, err := l.Parse()
				if err != nil {
					errs = append(errs, fmt.Errorf("parsing VCS locator: %w", err))
				} else if parts.Commit == "" {
					errs = append(errs, errors.New("remoter policies referenced by VCS locator require a digest or commit hash"))
				}
			} else if uri != "" {
				errs = append(errs, errors.New("remote policies referenced by URL require at least one hash"))
			}
		} else {
			for algo := range ref.GetLocation().GetDigest() {
				if _, ok := intoto.HashAlgorithms[algo]; !ok {
					errs = append(errs, fmt.Errorf("unknown algorithm %q in reference digest", algo))
				}
			}
		}
	}

	// TODO Check hash algorithms to be valid (from the intoto catalog)

	return errors.Join(errs...)
}

// Validate validates the policy structure to ensure fields and structural values
// are correct. Still needs work.
func (p *Policy) Validate() error {
	errs := []error{}

	for key, def := range p.GetContext() {
		if err := def.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("invalid context definition for %q: %w", key, err))
		}
	}

	for _, i := range p.GetIdentities() {
		if err := i.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := p.GetWhen().Validate(); err != nil {
		errs = append(errs, fmt.Errorf("policy %q: %w", p.GetId(), err))
	}

	return errors.Join(errs...)
}

// GetOrigin returns the coordinates where the predicate data originated from.
func (p *Policy) GetOrigin() attestation.Subject {
	if p.GetMeta() == nil {
		return nil
	}
	return p.GetMeta().GetOrigin()
}

// SetOrigin sets the origin of the policy. It is designed to match the signature
// of the attestation.Predicate method, but if the argument is a resource descriptor,
// then we will clone it and use its value.
func (p *Policy) SetOrigin(origin attestation.Subject) {
	if p.GetMeta() == nil {
		p.Meta = &Meta{}
	}

	rd, ok := origin.(*intoto.ResourceDescriptor)
	if ok {
		msg := proto.Clone(rd)
		nrd, ok := msg.(*intoto.ResourceDescriptor)
		if ok {
			p.Meta.Origin = nrd
			return
		}
	}

	p.Meta.Origin = &intoto.ResourceDescriptor{
		Name:   origin.GetName(),
		Uri:    origin.GetUri(),
		Digest: origin.GetDigest(),
	}
}

// The following functions allow the policy and policset to implement the predicate
// interface te be able to be wrapped in an intoto statement

// ContextMap compiles the context data values into a map, filling the fields
// with their defaults when needed. Entries whose value is resolved dynamically
// via an `expression` are skipped: they cannot be known without an evaluator
// and an evaluation context.
func (p *Policy) ContextMap() map[string]any {
	ret := map[string]any{}
	for label, value := range p.Context {
		if value.GetExpression() != "" {
			continue
		}
		if value.Value != nil {
			ret[label] = value.Value.AsInterface()
		} else {
			ret[label] = value.Default.AsInterface()
		}
	}
	return ret
}

// PublicKeys returns any public keys defined in the policy identities
func (p *Policy) PublicKeys() ([]key.PublicKeyProvider, error) {
	keys := []key.PublicKeyProvider{}
	for _, id := range p.GetIdentities() {
		k, err := id.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		if k != nil {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// Label returns the unified label for the control
func (ctl *Control) Label() string {
	// This requires an id in the control.
	if ctl.Id == "" {
		return ""
	}

	// The most basic label is the control ID
	label := ctl.Id

	// We support both classed and classless controls
	if ctl.Class != "" {
		label = ctl.Class + "-" + label
	}
	if ctl.Framework != "" {
		label = ctl.GetFramework() + "-" + label
	}

	return label
}
