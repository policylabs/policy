// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package options

import "fmt"

// Default limit values
const (
	DefaultMaxInputSize        int64 = 10 * 1024 * 1024 // 10 MiB
	DefaultMaxJSONDepth        int   = 100
	DefaultMaxPoliciesPerSet   int   = 1000
	DefaultMaxGroupsPerSet     int   = 100
	DefaultMaxBlocksPerGroup   int   = 100
	DefaultMaxPoliciesPerBlock int   = 100
	DefaultMaxTenetsPerPolicy  int   = 500
	DefaultMaxParallelFetches  int   = 50
	DefaultMaxTotalFetches     int   = 100
)

// Limits defines limits to protect against denial-of-service attacks
// when reading and processing policies.
type Limits struct {
	// MaxInputSize is the maximum size in bytes for input files and network responses.
	// Default: 10 MiB
	MaxInputSize int64

	// MaxJSONDepth is the maximum nesting depth allowed in JSON/HJSON input.
	// Prevents stack overflow attacks from deeply nested structures.
	// Default: 100
	MaxJSONDepth int

	// MaxPoliciesPerSet is the maximum number of policies allowed in a PolicySet.
	// Default: 1000
	MaxPoliciesPerSet int

	// MaxGroupsPerSet is the maximum number of policy groups allowed in a PolicySet.
	// Default: 100
	MaxGroupsPerSet int

	// MaxBlocksPerGroup is the maximum number of blocks allowed in a PolicyGroup.
	// Default: 100
	MaxBlocksPerGroup int

	// MaxPoliciesPerBlock is the maximum number of policies allowed per block in a PolicyGroup.
	// Default: 100
	MaxPoliciesPerBlock int

	// MaxTenetsPerPolicy is the maximum number of tenets allowed in a Policy.
	// Default: 500
	MaxTenetsPerPolicy int

	// MaxParallelFetches is the maximum number of concurrent remote fetches.
	// Default: 50
	MaxParallelFetches int

	// MaxTotalFetches is the maximum total number of remote fetches during compilation.
	// Prevents exponential expansion attacks.
	// Default: 100
	MaxTotalFetches int
}

// DefaultLimits provides sensible default limits for DoS protection.
var DefaultLimits = Limits{
	MaxInputSize:        DefaultMaxInputSize,
	MaxJSONDepth:        DefaultMaxJSONDepth,
	MaxPoliciesPerSet:   DefaultMaxPoliciesPerSet,
	MaxGroupsPerSet:     DefaultMaxGroupsPerSet,
	MaxBlocksPerGroup:   DefaultMaxBlocksPerGroup,
	MaxPoliciesPerBlock: DefaultMaxPoliciesPerBlock,
	MaxTenetsPerPolicy:  DefaultMaxTenetsPerPolicy,
	MaxParallelFetches:  DefaultMaxParallelFetches,
	MaxTotalFetches:     DefaultMaxTotalFetches,
}

// LimitError represents a limit violation error with context.
type LimitError struct {
	// Limit is the name of the limit that was exceeded
	Limit string
	// Max is the configured maximum value
	Max int64
	// Actual is the actual value that exceeded the limit
	Actual int64
	// Context provides additional context (e.g., file path, URL)
	Context string
}

func (e *LimitError) Error() string {
	if e.Context != "" {
		return fmt.Sprintf("%s limit exceeded: limit=%d, actual=%d (%s)", e.Limit, e.Max, e.Actual, e.Context)
	}
	return fmt.Sprintf("%s limit exceeded: limit=%d, actual=%d", e.Limit, e.Max, e.Actual)
}

// Sentinel errors for specific limit violations
var (
	ErrInputSizeExceeded        = &LimitError{Limit: "input size"}
	ErrJSONDepthExceeded        = &LimitError{Limit: "JSON depth"}
	ErrPoliciesPerSetExceeded   = &LimitError{Limit: "policies per set"}
	ErrGroupsPerSetExceeded     = &LimitError{Limit: "groups per set"}
	ErrBlocksPerGroupExceeded   = &LimitError{Limit: "blocks per group"}
	ErrPoliciesPerBlockExceeded = &LimitError{Limit: "policies per block"}
	ErrTenetsPerPolicyExceeded  = &LimitError{Limit: "tenets per policy"}
	ErrParallelFetchesExceeded  = &LimitError{Limit: "parallel fetches"}
	ErrTotalFetchesExceeded     = &LimitError{Limit: "total fetches"}
)

// NewInputSizeError creates a new input size limit error.
func NewInputSizeError(maxVal, actual int64, context string) *LimitError {
	return &LimitError{
		Limit:   "input size",
		Max:     maxVal,
		Actual:  actual,
		Context: context,
	}
}

// NewJSONDepthError creates a new JSON depth limit error.
func NewJSONDepthError(maxVal, actual int, context string) *LimitError {
	return &LimitError{
		Limit:   "JSON depth",
		Max:     int64(maxVal),
		Actual:  int64(actual),
		Context: context,
	}
}

// NewCollectionSizeError creates a new collection size limit error.
func NewCollectionSizeError(limitName string, maxVal, actual int, context string) *LimitError {
	return &LimitError{
		Limit:   limitName,
		Max:     int64(maxVal),
		Actual:  int64(actual),
		Context: context,
	}
}

// NewTotalFetchesError creates a new total fetches limit error.
func NewTotalFetchesError(maxVal, actual int, context string) *LimitError {
	return &LimitError{
		Limit:   "total fetches",
		Max:     int64(maxVal),
		Actual:  int64(actual),
		Context: context,
	}
}

// Functional options for configuring limits

// WithMaxInputSize sets the maximum input size limit.
func WithMaxInputSize(size int64) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxInputSize = size
		case *CompileOptions:
			o.Limits.MaxInputSize = size
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxJSONDepth sets the maximum JSON nesting depth limit.
func WithMaxJSONDepth(depth int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxJSONDepth = depth
		case *CompileOptions:
			o.Limits.MaxJSONDepth = depth
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxPoliciesPerSet sets the maximum policies per set limit.
func WithMaxPoliciesPerSet(maxVal int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxPoliciesPerSet = maxVal
		case *CompileOptions:
			o.Limits.MaxPoliciesPerSet = maxVal
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxGroupsPerSet sets the maximum groups per set limit.
func WithMaxGroupsPerSet(maxVal int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxGroupsPerSet = maxVal
		case *CompileOptions:
			o.Limits.MaxGroupsPerSet = maxVal
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxBlocksPerGroup sets the maximum blocks per group limit.
func WithMaxBlocksPerGroup(maxVal int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxBlocksPerGroup = maxVal
		case *CompileOptions:
			o.Limits.MaxBlocksPerGroup = maxVal
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxPoliciesPerBlock sets the maximum policies per block limit.
func WithMaxPoliciesPerBlock(maxVal int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxPoliciesPerBlock = maxVal
		case *CompileOptions:
			o.Limits.MaxPoliciesPerBlock = maxVal
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxTenetsPerPolicy sets the maximum tenets per policy limit.
func WithMaxTenetsPerPolicy(maxVal int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxTenetsPerPolicy = maxVal
		case *CompileOptions:
			o.Limits.MaxTenetsPerPolicy = maxVal
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxParallelFetches sets the maximum parallel fetches limit.
func WithMaxParallelFetches(maxVal int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxParallelFetches = maxVal
		case *CompileOptions:
			o.Limits.MaxParallelFetches = maxVal
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithMaxTotalFetches sets the maximum total fetches limit.
func WithMaxTotalFetches(maxVal int) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits.MaxTotalFetches = maxVal
		case *CompileOptions:
			o.Limits.MaxTotalFetches = maxVal
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithLimits sets all limits at once.
func WithLimits(limits Limits) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.Limits = limits
		case *CompileOptions:
			o.Limits = limits
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}
