// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	intoto "github.com/in-toto/attestation/go/v1"
	sapi "github.com/policylabs/signer/api/v1"
)

var (
	_ RemoteReference = &PolicyRef{}
	_ RemoteReference = &PolicyGroupRef{}
)

// RemoteReference is an interface to handle policy and group references
type RemoteReference interface {
	GetId() string
	GetIdentity() *sapi.Identity
	GetLocation() *intoto.ResourceDescriptor
	GetSourceURL() string
	GetVersion() int64
	SetVersion(int64)
}

type ChainProvider interface {
	GetChain() []*ChainLink
}

type CommonProvider interface {
	GetCommon() *PolicySetCommon
}
