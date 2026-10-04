// SPDX-FileCopyrightText: Copyright 2025 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/policy/options"
)

func TestLimits_InputSizeExceeded(t *testing.T) {
	t.Parallel()

	// Create a temporary file larger than the limit
	tmpDir := t.TempDir()
	largePath := filepath.Join(tmpDir, "large.json")

	// Create a file with content larger than 100 bytes
	largeContent := `{"id":"` + strings.Repeat("x", 200) + `"}`
	err := os.WriteFile(largePath, []byte(largeContent), 0o600)
	require.NoError(t, err)

	parser := NewParser()

	// Test with a very small limit
	_, err = parser.ParsePolicyFile(largePath, options.WithMaxInputSize(100))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "input size limit exceeded")
}

func TestLimits_InputSizeAllowed(t *testing.T) {
	t.Parallel()

	// Create a temporary file within the limit
	tmpDir := t.TempDir()
	smallPath := filepath.Join(tmpDir, "small.json")

	smallContent := `{"id":"test-policy"}`
	err := os.WriteFile(smallPath, []byte(smallContent), 0o600)
	require.NoError(t, err)

	parser := NewParser()

	// Test with a generous limit
	policy, err := parser.ParsePolicyFile(smallPath, options.WithMaxInputSize(1024*1024))
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "test-policy", policy.Id)
}

func TestLimits_JSONDepthExceeded(t *testing.T) {
	t.Parallel()

	// Create deeply nested JSON
	depth := 50
	nested := strings.Repeat(`{"a":`, depth) + `"value"` + strings.Repeat(`}`, depth)

	parser := NewParser()

	// Test with a small depth limit
	_, err := parser.ParsePolicy([]byte(nested), options.WithMaxJSONDepth(10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON depth limit exceeded")
}

func TestLimits_JSONDepthAllowed(t *testing.T) {
	t.Parallel()

	// Create a policy with normal nesting
	policyJSON := `{
		"id": "test-policy",
		"meta": {
			"description": "Test policy"
		},
		"tenets": [{
			"id": "test-tenet",
			"code": "true"
		}]
	}`

	parser := NewParser()

	// Test with default limits
	policy, err := parser.ParsePolicy([]byte(policyJSON))
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "test-policy", policy.Id)
}

func TestLimits_PoliciesPerSetExceeded(t *testing.T) {
	t.Parallel()

	// Create a policy set with many policies
	policies := make([]string, 15)
	for i := range policies {
		policies[i] = `{"id":"policy-` + string(rune('0'+i%10)) + string(rune('0'+i/10)) + `"}`
	}

	policySetJSON := `{
		"id": "test-set",
		"policies": [` + strings.Join(policies, ",") + `]
	}`

	parser := NewParser()

	// Test with a small limit
	_, err := parser.ParsePolicySet([]byte(policySetJSON), options.WithMaxPoliciesPerSet(10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policies per set limit exceeded")
}

func TestLimits_PoliciesPerSetAllowed(t *testing.T) {
	t.Parallel()

	policySetJSON := `{
		"id": "test-set",
		"policies": [
			{"id": "policy-1"},
			{"id": "policy-2"}
		]
	}`

	parser := NewParser()

	// Test with default limits
	policySet, err := parser.ParsePolicySet([]byte(policySetJSON))
	require.NoError(t, err)
	require.NotNil(t, policySet)
	assert.Equal(t, "test-set", policySet.Id)
	assert.Len(t, policySet.Policies, 2)
}

func TestLimits_TenetsPerPolicyExceeded(t *testing.T) {
	t.Parallel()

	// Create a policy with many tenets
	tenets := make([]string, 15)
	for i := range tenets {
		tenets[i] = `{"id":"tenet-` + string(rune('0'+i%10)) + string(rune('0'+i/10)) + `","code":"true"}`
	}

	policyJSON := `{
		"id": "test-policy",
		"tenets": [` + strings.Join(tenets, ",") + `]
	}`

	parser := NewParser()

	// Test with a small limit
	_, err := parser.ParsePolicy([]byte(policyJSON), options.WithMaxTenetsPerPolicy(10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenets per policy limit exceeded")
}

func TestLimits_TenetsPerPolicyAllowed(t *testing.T) {
	t.Parallel()

	policyJSON := `{
		"id": "test-policy",
		"tenets": [
			{"id": "tenet-1", "code": "true"},
			{"id": "tenet-2", "code": "false"}
		]
	}`

	parser := NewParser()

	// Test with default limits
	policy, err := parser.ParsePolicy([]byte(policyJSON))
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "test-policy", policy.Id)
	assert.Len(t, policy.Tenets, 2)
}

func TestLimits_BlocksPerGroupExceeded(t *testing.T) {
	t.Parallel()

	// Create a policy group with many blocks
	blocks := make([]string, 15)
	for i := range blocks {
		blocks[i] = `{"id":"block-` + string(rune('0'+i%10)) + string(rune('0'+i/10)) + `"}`
	}

	groupJSON := `{
		"id": "test-group",
		"blocks": [` + strings.Join(blocks, ",") + `]
	}`

	parser := NewParser()

	// Test with a small limit
	_, err := parser.ParsePolicyGroup([]byte(groupJSON), options.WithMaxBlocksPerGroup(10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocks per group limit exceeded")
}

func TestLimits_BlocksPerGroupAllowed(t *testing.T) {
	t.Parallel()

	groupJSON := `{
		"id": "test-group",
		"blocks": [
			{"id": "block-1"},
			{"id": "block-2"}
		]
	}`

	parser := NewParser()

	// Test with default limits
	group, err := parser.ParsePolicyGroup([]byte(groupJSON))
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "test-group", group.Id)
	assert.Len(t, group.Blocks, 2)
}

func TestLimits_PoliciesPerBlockExceeded(t *testing.T) {
	t.Parallel()

	// Create a policy group with a block that has many policies
	policies := make([]string, 15)
	for i := range policies {
		policies[i] = `{"id":"policy-` + string(rune('0'+i%10)) + string(rune('0'+i/10)) + `"}`
	}

	groupJSON := `{
		"id": "test-group",
		"blocks": [{
			"id": "block-1",
			"policies": [` + strings.Join(policies, ",") + `]
		}]
	}`

	parser := NewParser()

	// Test with a small limit
	_, err := parser.ParsePolicyGroup([]byte(groupJSON), options.WithMaxPoliciesPerBlock(10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policies per block limit exceeded")
}

func TestLimits_GroupsPerSetExceeded(t *testing.T) {
	t.Parallel()

	// Create a policy set with many groups
	groups := make([]string, 15)
	for i := range groups {
		groups[i] = `{"id":"group-` + string(rune('0'+i%10)) + string(rune('0'+i/10)) + `"}`
	}

	policySetJSON := `{
		"id": "test-set",
		"groups": [` + strings.Join(groups, ",") + `]
	}`

	parser := NewParser()

	// Test with a small limit
	_, err := parser.ParsePolicySet([]byte(policySetJSON), options.WithMaxGroupsPerSet(10))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "groups per set limit exceeded")
}

func TestLimits_FunctionalOptions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		optFn  options.OptFn
		verify func(t *testing.T, opts *options.ParseOptions)
	}{
		{
			name:  "WithMaxInputSize",
			optFn: options.WithMaxInputSize(5 * 1024 * 1024),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, int64(5*1024*1024), opts.Limits.MaxInputSize)
			},
		},
		{
			name:  "WithMaxJSONDepth",
			optFn: options.WithMaxJSONDepth(50),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 50, opts.Limits.MaxJSONDepth)
			},
		},
		{
			name:  "WithMaxPoliciesPerSet",
			optFn: options.WithMaxPoliciesPerSet(500),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 500, opts.Limits.MaxPoliciesPerSet)
			},
		},
		{
			name:  "WithMaxGroupsPerSet",
			optFn: options.WithMaxGroupsPerSet(50),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 50, opts.Limits.MaxGroupsPerSet)
			},
		},
		{
			name:  "WithMaxBlocksPerGroup",
			optFn: options.WithMaxBlocksPerGroup(50),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 50, opts.Limits.MaxBlocksPerGroup)
			},
		},
		{
			name:  "WithMaxPoliciesPerBlock",
			optFn: options.WithMaxPoliciesPerBlock(50),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 50, opts.Limits.MaxPoliciesPerBlock)
			},
		},
		{
			name:  "WithMaxTenetsPerPolicy",
			optFn: options.WithMaxTenetsPerPolicy(250),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 250, opts.Limits.MaxTenetsPerPolicy)
			},
		},
		{
			name:  "WithMaxParallelFetches",
			optFn: options.WithMaxParallelFetches(25),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 25, opts.Limits.MaxParallelFetches)
			},
		},
		{
			name:  "WithMaxTotalFetches",
			optFn: options.WithMaxTotalFetches(50),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, 50, opts.Limits.MaxTotalFetches)
			},
		},
		{
			name: "WithLimits",
			optFn: options.WithLimits(options.Limits{
				MaxInputSize:        1024,
				MaxJSONDepth:        20,
				MaxPoliciesPerSet:   100,
				MaxGroupsPerSet:     10,
				MaxBlocksPerGroup:   10,
				MaxPoliciesPerBlock: 10,
				MaxTenetsPerPolicy:  50,
				MaxParallelFetches:  5,
				MaxTotalFetches:     10,
			}),
			verify: func(t *testing.T, opts *options.ParseOptions) {
				assert.Equal(t, int64(1024), opts.Limits.MaxInputSize)
				assert.Equal(t, 20, opts.Limits.MaxJSONDepth)
				assert.Equal(t, 100, opts.Limits.MaxPoliciesPerSet)
				assert.Equal(t, 10, opts.Limits.MaxGroupsPerSet)
				assert.Equal(t, 10, opts.Limits.MaxBlocksPerGroup)
				assert.Equal(t, 10, opts.Limits.MaxPoliciesPerBlock)
				assert.Equal(t, 50, opts.Limits.MaxTenetsPerPolicy)
				assert.Equal(t, 5, opts.Limits.MaxParallelFetches)
				assert.Equal(t, 10, opts.Limits.MaxTotalFetches)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			opts := options.DefaultParseOptions
			err := tt.optFn(&opts)
			require.NoError(t, err)
			tt.verify(t, &opts)
		})
	}
}

func TestLimits_DefaultValues(t *testing.T) {
	t.Parallel()

	// Verify default values are set correctly
	defaults := options.DefaultLimits

	assert.Equal(t, int64(10*1024*1024), defaults.MaxInputSize)
	assert.Equal(t, 100, defaults.MaxJSONDepth)
	assert.Equal(t, 1000, defaults.MaxPoliciesPerSet)
	assert.Equal(t, 100, defaults.MaxGroupsPerSet)
	assert.Equal(t, 100, defaults.MaxBlocksPerGroup)
	assert.Equal(t, 100, defaults.MaxPoliciesPerBlock)
	assert.Equal(t, 500, defaults.MaxTenetsPerPolicy)
	assert.Equal(t, 50, defaults.MaxParallelFetches)
	assert.Equal(t, 100, defaults.MaxTotalFetches)
}

func TestLimits_LimitError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      *options.LimitError
		expected string
	}{
		{
			name: "WithContext",
			err: &options.LimitError{
				Limit:   "input size",
				Max:     1024,
				Actual:  2048,
				Context: "/path/to/file.json",
			},
			expected: "input size limit exceeded: limit=1024, actual=2048 (/path/to/file.json)",
		},
		{
			name: "WithoutContext",
			err: &options.LimitError{
				Limit:  "JSON depth",
				Max:    100,
				Actual: 150,
			},
			expected: "JSON depth limit exceeded: limit=100, actual=150",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestLimits_ErrorConstructors(t *testing.T) {
	t.Parallel()

	t.Run("NewInputSizeError", func(t *testing.T) {
		t.Parallel()
		err := options.NewInputSizeError(1024, 2048, "/test/file.json")
		assert.Equal(t, "input size", err.Limit)
		assert.Equal(t, int64(1024), err.Max)
		assert.Equal(t, int64(2048), err.Actual)
		assert.Equal(t, "/test/file.json", err.Context)
	})

	t.Run("NewJSONDepthError", func(t *testing.T) {
		t.Parallel()
		err := options.NewJSONDepthError(100, 150, "")
		assert.Equal(t, "JSON depth", err.Limit)
		assert.Equal(t, int64(100), err.Max)
		assert.Equal(t, int64(150), err.Actual)
	})

	t.Run("NewCollectionSizeError", func(t *testing.T) {
		t.Parallel()
		err := options.NewCollectionSizeError("policies per set", 100, 150, "test-set")
		assert.Equal(t, "policies per set", err.Limit)
		assert.Equal(t, int64(100), err.Max)
		assert.Equal(t, int64(150), err.Actual)
		assert.Equal(t, "test-set", err.Context)
	})

	t.Run("NewTotalFetchesError", func(t *testing.T) {
		t.Parallel()
		err := options.NewTotalFetchesError(100, 150, "")
		assert.Equal(t, "total fetches", err.Limit)
		assert.Equal(t, int64(100), err.Max)
		assert.Equal(t, int64(150), err.Actual)
	})
}

func TestLimits_ExistingTestdataParses(t *testing.T) {
	t.Parallel()

	// Verify that existing testdata files parse correctly with default limits
	testdataDir := "testdata"
	if _, err := os.Stat(testdataDir); os.IsNotExist(err) {
		t.Skip("testdata directory not found")
	}

	err := filepath.Walk(testdataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		t.Run(path, func(t *testing.T) {
			parser := NewParser()
			_, _, _, err := parser.Open(path)
			// Some test files may intentionally be invalid, so we just check
			// that we don't get a limit error
			if err != nil {
				assert.NotContains(t, err.Error(), "limit exceeded",
					"testdata file should not exceed default limits")
			}
		})
		return nil
	})
	require.NoError(t, err)
}

func TestCheckJSONDepth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		json         string
		maxDepth     int
		expectError  bool
		expectedMax  int
		errorContain string
	}{
		{
			name:        "FlatObject",
			json:        `{"a": 1, "b": 2}`,
			maxDepth:    10,
			expectError: false,
			expectedMax: 1,
		},
		{
			name:        "NestedObject",
			json:        `{"a": {"b": {"c": 1}}}`,
			maxDepth:    10,
			expectError: false,
			expectedMax: 3,
		},
		{
			name:        "NestedArray",
			json:        `[[[1]]]`,
			maxDepth:    10,
			expectError: false,
			expectedMax: 3,
		},
		{
			name:        "MixedNesting",
			json:        `{"a": [{"b": [1]}]}`,
			maxDepth:    10,
			expectError: false,
			expectedMax: 4,
		},
		{
			name:         "ExceedsLimit",
			json:         `{"a": {"b": {"c": {"d": {"e": 1}}}}}`,
			maxDepth:     3,
			expectError:  true,
			errorContain: "JSON depth limit exceeded",
		},
		{
			name:        "ZeroLimitDisablesCheck",
			json:        `{"a": {"b": {"c": {"d": {"e": 1}}}}}`,
			maxDepth:    0,
			expectError: false,
			expectedMax: 0, // No check performed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			maxObserved, err := checkJSONDepth([]byte(tt.json), tt.maxDepth)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContain)
			} else {
				require.NoError(t, err)
				if tt.maxDepth > 0 {
					assert.Equal(t, tt.expectedMax, maxObserved)
				}
			}
		})
	}
}
