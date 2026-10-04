# Tooling Reference

This document provides detailed documentation for the policy tooling components: the **Parser**, **Compiler**, and **Storage Backend**.

## Table of Contents

- [Parser](#parser)
  - [What the Parser Does](#what-the-parser-does)
  - [Supported Formats](#supported-formats)
  - [Parsing Methods](#parsing-methods)
  - [Signature Verification](#signature-verification)
  - [Parse Options](#parse-options)
- [Compiler](#compiler)
  - [What the Compiler Does](#what-the-compiler-does)
  - [Compilation Process](#compilation-process)
  - [Compilation Methods](#compilation-methods)
  - [Compiler Options](#compiler-options)
  - [Remote Resource Fetching](#remote-resource-fetching)
  - [Assembly Process](#assembly-process)
- [Storage Backend](#storage-backend)
  - [What the Storage Backend Does](#what-the-storage-backend-does)
  - [Indexing and Caching](#indexing-and-caching)
  - [Lookup Methods](#lookup-methods)
  - [Content Deduplication](#content-deduplication)
- [Usage Examples](#usage-examples)

---

## Parser

The **Parser** is responsible for reading policy files and converting them from JSON/HJSON format into structured protocol buffer objects.

### What the Parser Does

The parser handles:

1. **Format normalization**: Accepts both JSON and HJSON (human-friendly JSON with comments)
2. **Envelope detection**: Recognizes when policies are wrapped in cryptographic signature envelopes
3. **Signature verification**: Optionally verifies signatures on policy files
4. **Deserialization**: Converts JSON to strongly-typed protobuf objects
5. **Default application**: Applies default values for optional fields (e.g., `enforce: ON`, `assert_mode: AND`)
6. **Content hashing**: Computes and records content hashes in the policy's origin metadata

### Supported Formats

#### JSON

Standard JSON format:

```json
{
  "id": "my-policy",
  "meta": {
    "description": "Policy description"
  },
  "tenets": [
    {
      "id": "check-1",
      "code": "true"
    }
  ]
}
```

#### HJSON

Human JSON - more forgiving syntax with comments:

```hjson
{
  # This is a comment
  id: my-policy  # No quotes needed for simple strings
  meta: {
    description: Policy description
  }
  tenets: [
    {
      id: check-1
      code: "true"
    }
  ]
}
```

The parser automatically detects and converts HJSON to JSON before processing.

#### Signed Envelopes

Policies can be wrapped in cryptographic signature envelopes (using in-toto attestation format):

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "base64-encoded-policy",
  "signatures": [...]
}
```

The parser automatically detects envelopes and extracts the policy content, optionally verifying signatures.

### Parsing Methods

#### Creating a Parser

```go
parser := policy.NewParser()
```

#### Parsing from Files

**PolicySet from file**:
```go
policySet, err := parser.ParsePolicySetFile("path/to/policyset.json")
```

**Policy from file**:
```go
pcy, err := parser.ParsePolicyFile("path/to/policy.json")
```

**PolicyGroup from file**:
```go
group, err := parser.ParsePolicyGroupFile("path/to/group.json")
```

#### Parsing from Byte Slices

**PolicySet from bytes**:
```go
policySet, err := parser.ParsePolicySet(jsonData)
```

**Policy from bytes**:
```go
pcy, err := parser.ParsePolicy(jsonData)
```

**PolicyGroup from bytes**:
```go
group, err := parser.ParsePolicyGroup(jsonData)
```

#### Auto-detecting Type

Parse data that could be any policy material type:

```go
set, pcy, group, err := parser.ParseVerifyPolicyOrSetOrGroup(data)
// Exactly one of set, pcy, or group will be non-nil
```

#### Parsing from Remote Locations

The parser can fetch and parse from remote locations:

```go
set, pcy, group, err := parser.Open("git+https://github.com/org/repo@sha#policy.json")
set, pcy, group, err := parser.Open("https://example.com/policy.json")
set, pcy, group, err := parser.Open("/local/path/policy.json")
```

Supported location types:
- Local file paths
- HTTPS URLs
- Git VCS locators (`git+https://...`, `git+ssh://...`)

### Signature Verification

The parser can verify cryptographic signatures on policy files when they're wrapped in signature envelopes.

#### Parsing with Verification

All parsing methods have `*Verify` variants that return verification results:

```go
policySet, verification, err := parser.ParseVerifyPolicySet(data)

if verification != nil {
  // Check if signature was valid
  if verification.GetSignature().GetVerified() {
    // Signature valid, examine identities
    for _, identity := range verification.GetSignature().GetIdentities() {
      fmt.Printf("Signed by: %s\n", identity)
    }
  }
}
```

#### Verification Options

Control signature verification via parse options:

```go
opts := options.WithVerifySignatures(true)
opts = options.WithIdentityStrings([]string{
  "sigstore:https://token.actions.githubusercontent.com:https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
})

policySet, verification, err := parser.ParseVerifyPolicySet(data, opts)
```

### Parse Options

Parse options control parser behavior:

```go
import "github.com/policylabs/policy/options"

// Verify signatures
opts := options.WithVerifySignatures(true)

// Specify allowed signer identities
opts = options.WithIdentityStrings([]string{
  "sigstore:issuer:identity",
  "key:key-id",
})

// Provide public keys for verification
opts = options.WithPublicKeys([]crypto.PublicKey{pubKey})

policySet, err := parser.ParsePolicySet(data, opts)
```

### Default Values Applied by Parser

The parser applies defaults for optional fields:

| Field | Default | Applied To |
|-------|---------|------------|
| `meta.enforce` | `ON` | Policy, PolicyGroup, PolicySet |
| `meta.assert_mode` | `AND` | Policy, PolicyBlock |
| `meta.runtime` | `cel@v0` | Policy, Tenet |

**Important**: Defaults are **not applied** to policies with remote sources. Remote policies get their defaults from the remote content during compilation.

### Origin Metadata

The parser computes content hashes and records origin information:

```go
policySet, err := parser.ParsePolicySetFile("my-policy.json")

// Origin metadata is populated:
origin := policySet.GetMeta().GetOrigin()
fmt.Printf("Name: %s\n", origin.GetName())
fmt.Printf("SHA-256: %s\n", origin.GetDigest()["sha256"])
```

This enables:
- Content integrity verification
- Provenance tracking
- Reproducible builds

---

## Compiler

The **Compiler** assembles complete, executable policies by resolving remote references, fetching remote content, and validating the final structure.

### What the Compiler Does

The compiler:

1. **Parses** input data (using the Parser)
2. **Extracts** all remote references from the policy structure
3. **Fetches** remote policy materials from git repositories or HTTPS URLs
4. **Caches** fetched content in the storage backend
5. **Assembles** remote content into the local policy structure
6. **Validates** the complete, assembled policy
7. **Returns** a fully-resolved policy ready for evaluation

### Compilation Process

#### Step-by-Step

1. **Parse**: Convert JSON to policy objects
2. **Validate**: Check initial structure is valid
3. **Extract References**: Find all `source` fields pointing to remote content
4. **Fetch**: Download remote content in parallel
5. **Store**: Cache fetched content by hash and URL
6. **Assemble**: Replace references with actual policy content
7. **Validate**: Ensure assembled structure is complete and valid

#### Visual Flow

```
Input JSON
    ↓
[Parser] → Policy/Set/Group object
    ↓
[Extract] → List of remote references
    ↓
[Fetch] → Download from git/https (parallel)
    ↓
[Store] → Cache in storage backend
    ↓
[Assemble] → Replace refs with content
    ↓
[Validate] → Check final structure
    ↓
Complete Policy
```

### Compilation Methods

#### Creating a Compiler

```go
compiler := policy.NewCompiler()

// Or with custom options:
compiler := &policy.Compiler{
  Options: policy.CompilerOptions{
    MaxRemoteRecursion: 5,
  },
  Store: customStorageBackend,
  // impl is set automatically
}
```

#### Compiling from Various Sources

**From file**:
```go
set, pcy, group, err := compiler.CompileFile("path/to/policy.json")
```

**From remote location**:
```go
set, pcy, group, err := compiler.CompileLocation("git+https://github.com/org/repo@sha#policy.json")
set, pcy, group, err := compiler.CompileLocation("https://example.com/policy.json")
```

**From bytes**:
```go
set, pcy, group, err := compiler.Compile(jsonData)
```

#### Compiling Specific Types

If you know the type, you can compile directly:

**PolicySet**:
```go
policySet, err := parser.ParsePolicySetFile("policyset.json")
compiledSet, err := compiler.CompileSet(policySet)
```

**Policy**:
```go
pcy, err := parser.ParsePolicyFile("policy.json")
compiledPolicy, err := compiler.CompilePolicy(pcy)
```

**PolicyGroup**:
```go
group, err := parser.ParsePolicyGroupFile("group.json")
compiledGroup, err := compiler.CompilePolicyGroup(group)
```

#### Compilation with Verification

Like the parser, compilation methods have `*Verify` variants:

```go
set, pcy, group, verification, err := compiler.CompileVerifyLocation(location)
```

### Compiler Options

Configure compiler behavior:

```go
type CompilerOptions struct {
  MaxRemoteRecursion int // Maximum depth for nested remote references (default: 3)
}
```

**MaxRemoteRecursion**: Limits how many levels deep the compiler will follow remote references. For example:
- Level 1: PolicySet references remote Policy A
- Level 2: Policy A references remote Policy B
- Level 3: Policy B references remote Policy C
- Level 4: Would be rejected if MaxRemoteRecursion = 3

This prevents infinite recursion and excessive network requests.

### Remote Resource Fetching

The compiler fetches remote resources intelligently:

#### Parallel Fetching

All remote references at the same level are fetched in parallel for performance:

```go
// If a PolicySet references 10 remote policies,
// all 10 are fetched concurrently
```

#### Content Verification

The compiler verifies fetched content:

1. **Hash verification**: If `digest` is specified in the reference, compute fetched content's hash and compare
2. **Signature verification**: If enabled, verify signatures on remote policy envelopes
3. **Type validation**: Ensure fetched content is the expected type (Policy, PolicyGroup, or PolicySet)

Example with hash verification:

```json
{
  "source": {
    "location": {
      "uri": "https://example.com/policy.json",
      "digest": {
        "sha256": "expected-hash"
      }
    }
  }
}
```

If the fetched content's SHA-256 doesn't match `expected-hash`, compilation fails.

#### Recursive Compilation

When a remote policy itself contains remote references, they're compiled recursively:

```
PolicySet (local)
  ├─ Policy A (remote)
  │   └─ references Policy B (remote)
  │       └─ references Policy C (remote)
  └─ Policy D (local)
```

The compiler fetches A, then B, then C, assembling from the bottom up, respecting `MaxRemoteRecursion`.

### Assembly Process

During assembly, the compiler:

1. **Replaces source references** with actual content:
   ```go
   // Before assembly:
   policies[0].Source = &PolicyRef{Location: ...}

   // After assembly:
   policies[0].Source = nil  // Cleared
   policies[0].Tenets = [...] // Populated from remote content
   policies[0].Meta = {...}   // Merged with remote metadata
   ```

2. **Preserves metadata**: Important fields from remote policies (like `assert_mode`) are preserved, not overwritten by defaults

3. **Clears source fields**: After assembly, `source` is set to `nil` since the content is now local

4. **Records origin**: The `meta.origin` field tracks where content came from

#### PolicySet Assembly

For PolicySets:
- Remote policies are fetched and inserted into the `policies` array
- Remote groups are fetched and inserted into the `groups` array
- Common identities and context are available to all assembled policies

#### PolicyGroup Assembly

For PolicyGroups:
- If the group itself is a remote reference, fetch the entire group structure
- Policies within remote groups are assembled recursively

#### Policy Assembly

For Policies:
- Remote references are resolved to actual policy content
- Tenets, identities, and metadata are merged
- Context values are combined (policy-specific + common)

### Validation

The compiler performs validation at multiple stages:

**Before fetching**:
- Policy structure is well-formed
- References have valid URIs
- Required fields are present

**After assembly**:
- All remote references have been resolved
- No dangling references remain
- Combined structure is valid
- Identities are properly defined
- Context values are consistent

If validation fails at any stage, compilation returns an error.

---

## Storage Backend

The **Storage Backend** is a caching layer that optimizes remote content fetching by storing and indexing fetched policy materials.

### What the Storage Backend Does

The storage backend:

1. **Caches** fetched remote content to avoid duplicate downloads
2. **Indexes** content by multiple keys (hash, URL, ID)
3. **Deduplicates** content (same content referenced multiple ways is stored once)
4. **Provides fast lookups** for the compiler during assembly

### Indexing and Caching

When content is stored, it's indexed by:

1. **Content hash (SHA-256)**: Primary key
2. **Source URL**: For lookups by location
3. **Policy ID**: For lookups by identifier
4. **Other digests**: Any additional hashes in the resource descriptor

#### Storage Example

When you store a policy fetched from `https://example.com/policy.json`:

```go
store.StoreReference(reference)
```

The backend indexes it as:
- Hash: `sha256:abc123...` → Policy object
- URL: `https://example.com/policy.json` → Hash `abc123...`
- ID: `my-policy-id` → Hash `abc123...`

Later lookups by any of these keys return the same cached content.

### Lookup Methods

The storage backend interface provides several lookup methods:

```go
type StorageBackend interface {
  // Store a reference and its content
  StoreReference(api.RemoteReference) error
  StoreReferenceWithReturn(api.RemoteReference) (*api.PolicySet, *api.Policy, *api.PolicyGroup, error)

  // Retrieve by reference
  GetReferencedPolicy(api.RemoteReference) (*api.Policy, error)
  GetReferencedGroup(api.RemoteReference) (*api.PolicyGroup, error)
}
```

#### Internal Lookup Methods (refStore Implementation)

The default `refStore` implementation provides additional internal methods:

**By ID**:
```go
policy := store.GetPolicyByID("my-policy-id")
group := store.GetPolicyGroupByID("my-group-id")
```

**By URL**:
```go
policy := store.GetPolicyByURL("https://example.com/policy.json")
group := store.GetPolicyGroupByURL("https://example.com/group.json")
```

**By Hash**:
```go
policy := store.GetPolicyBySHA256("abc123...")
policySet := store.GetPolicySetBySHA256("def456...")
group := store.GetPolicyGroupBySHA256("789abc...")
```

### Content Deduplication

The storage backend automatically deduplicates content:

#### Scenario 1: Same URL Referenced Twice

```json
{
  "policies": [
    {"source": {"location": {"uri": "https://example.com/policy.json"}}},
    {"source": {"location": {"uri": "https://example.com/policy.json"}}}
  ]
}
```

The content is fetched once and both references use the cached copy.

#### Scenario 2: Different URLs, Same Content

```json
{
  "policies": [
    {"source": {"location": {"uri": "https://cdn1.example.com/policy.json"}}},
    {"source": {"location": {"uri": "https://cdn2.example.com/policy.json"}}}
  ]
}
```

If both URLs return the same content (same SHA-256), it's stored once under that hash, with both URLs indexed to it.

#### Scenario 3: Hash-Based Reference

```json
{
  "source": {
    "location": {
      "uri": "https://example.com/policy.json",
      "digest": {"sha256": "abc123..."}
    }
  }
}
```

If this content has already been fetched (by any URL), the hash lookup returns it immediately without re-fetching.

### Default Implementation: refStore

The default storage backend is `refStore`, an in-memory cache:

```go
type refStore struct {
  references   map[string]api.RemoteReference  // hash → reference
  policySets   map[string]*api.PolicySet       // hash → PolicySet
  policies     map[string]*api.Policy          // hash → Policy
  policyGroups map[string]*api.PolicyGroup     // hash → PolicyGroup
  ids          map[string]string               // id → hash
  urls         map[string]string               // url → hash
  hashes       map[string]string               // algorithm:value → hash
}
```

This implementation:
- Is created automatically by `NewCompiler()`
- Stores content in memory (not persisted)
- Provides fast lookups during compilation
- Is scoped to a single compilation session

#### Custom Storage Backends

You can implement custom storage backends for:
- **Persistent caching**: Store fetched content on disk or in a database
- **Distributed caching**: Share cached content across multiple compiler instances
- **Policy repositories**: Serve as a policy server

Implement the `StorageBackend` interface:

```go
type MyCustomStore struct {
  // Your implementation
}

func (s *MyCustomStore) StoreReference(ref api.RemoteReference) error {
  // Store logic
}

func (s *MyCustomStore) GetReferencedPolicy(ref api.RemoteReference) (*api.Policy, error) {
  // Retrieve logic
}

// ... implement other methods

compiler := &policy.Compiler{
  Options: defaultOptions,
  Store:   &MyCustomStore{},
  impl:    &defaultCompilerImpl{},
}
```

### Storage Workflow

Here's how the storage backend is used during compilation:

1. **Extract references**: Compiler finds all remote references
2. **Check cache**: For each reference, check if content is already in store (by URL or hash)
3. **Fetch if needed**: If not cached, fetch from remote location
4. **Store**: Parse fetched content and store in backend with indexes
5. **Assemble**: Retrieve cached content by reference and assemble into policy structure

This workflow minimizes network requests and speeds up compilation, especially for PolicySets with many references or repeated compilations of similar policies.

---

## Usage Examples

### Example 1: Parse and Compile a Local PolicySet

```go
package main

import (
  "fmt"
  "github.com/policylabs/policy"
)

func main() {
  // Create a compiler (includes parser)
  compiler := policy.NewCompiler()

  // Compile from file
  set, pcy, group, err := compiler.CompileFile("my-policyset.json")
  if err != nil {
    panic(err)
  }

  if set != nil {
    fmt.Printf("Compiled PolicySet: %s\n", set.GetId())
    fmt.Printf("Policies: %d\n", len(set.GetPolicies()))
    fmt.Printf("Groups: %d\n", len(set.GetGroups()))
  }
}
```

### Example 2: Compile from Remote Location

```go
compiler := policy.NewCompiler()

// Compile from git repository
uri := "git+https://github.com/myorg/policies@9a70ca49804c2b993bb6b62d51d5524f3443d6ec#policyset.json"
set, pcy, group, err := compiler.CompileLocation(uri)
if err != nil {
  panic(err)
}

fmt.Printf("Compiled remote PolicySet: %s\n", set.GetId())
```

### Example 3: Parse with Signature Verification

```go
import (
  "github.com/policylabs/policy"
  "github.com/policylabs/policy/options"
)

parser := policy.NewParser()

// Parse with signature verification enabled
opts := options.WithVerifySignatures(true)
opts = options.WithIdentityStrings([]string{
  "sigstore:https://token.actions.githubusercontent.com:https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
})

policySet, verification, err := parser.ParseVerifyPolicySetFile("signed-policy.json", opts)
if err != nil {
  panic(err)
}

if verification != nil && verification.GetSignature().GetVerified() {
  fmt.Println("Signature valid!")
  for _, id := range verification.GetSignature().GetIdentities() {
    fmt.Printf("Signed by: %v\n", id)
  }
} else {
  fmt.Println("Signature invalid or missing")
}
```

### Example 4: Custom Compiler Options

```go
import "github.com/policylabs/policy"

// Create compiler with custom options
compiler := &policy.Compiler{
  Options: policy.CompilerOptions{
    MaxRemoteRecursion: 5, // Allow deeper nesting
  },
  Store: policy.newRefStore(), // Use default store
  impl:  &policy.defaultCompilerImpl{},
}

set, pcy, group, err := compiler.CompileFile("complex-policy.json")
```

### Example 5: Compile PolicySet with Remote Policies

Given a PolicySet like:

```json
{
  "id": "my-set",
  "policies": [
    {
      "source": {
        "location": {
          "uri": "git+https://github.com/org/policies@sha#common/sbom.json"
        }
      }
    },
    {
      "source": {
        "location": {
          "uri": "https://policies.example.com/vuln-check.json",
          "digest": {
            "sha256": "abc123..."
          }
        }
      }
    }
  ]
}
```

Compile it:

```go
compiler := policy.NewCompiler()
set, _, _, err := compiler.CompileFile("my-policyset.json")
if err != nil {
  panic(err)
}

// After compilation:
// - Both remote policies have been fetched
// - Content has been verified (hash check for second policy)
// - Policies are assembled into the PolicySet
// - source fields are cleared, content is local
fmt.Printf("PolicySet has %d policies\n", len(set.GetPolicies()))

for i, p := range set.GetPolicies() {
  fmt.Printf("Policy %d: %s (source: %s)\n",
    i,
    p.GetId(),
    p.GetMeta().GetOrigin().GetUri())
}
```

### Example 6: Working with Storage Backend

```go
compiler := policy.NewCompiler()

// Compile first PolicySet (fetches remote content)
set1, _, _, _ := compiler.CompileFile("policyset1.json")

// Compile second PolicySet referencing same remote policies
// Content is retrieved from cache, not re-fetched
set2, _, _, _ := compiler.CompileFile("policyset2.json")

// The storage backend cached the remote content
// Both compilations use the same cached data
```

### Example 7: Parse HJSON Policy

```hjson
{
  # Human-friendly policy definition
  id: my-policy
  meta: {
    description: This policy checks SBOM licenses
    # Comments make policies more maintainable!
  }
  tenets: [
    {
      id: license-check
      code: "sbom.packages.all(p, p.license in allowed)"
    }
  ]
}
```

Parse it:

```go
parser := policy.NewParser()
pcy, err := parser.ParsePolicyFile("policy.hjson")
if err != nil {
  panic(err)
}

// HJSON is automatically converted to JSON and parsed
fmt.Printf("Parsed policy: %s\n", pcy.GetId())
```

---

## Integration with AMPEL

Once you've compiled a PolicySet, you pass it to the AMPEL policy engine for evaluation:

```go
import (
  "context"
  "github.com/policylabs/policy"
  "github.com/carabiner-dev/ampel/pkg/verifier"
  "github.com/carabiner-dev/attestation"
)

// Compile the policy
compiler := policy.NewCompiler()
set, _, _, err := compiler.CompileFile("my-policy.json")
if err != nil {
  panic(err)
}

// Create AMPEL verifier
ampel := verifier.New()

// Define the subject to verify (e.g., a container image digest)
subject := attestation.Subject{
  // Subject details (artifact being verified)
}

// Verify the subject against the compiled PolicySet
results, err := ampel.Verify(
  context.Background(),
  &verifier.VerificationOptions{
    // Configure verification options (attestation sources, context values, etc.)
  },
  set,  // Can be *Policy, *PolicySet, or []*PolicySet
  subject,
)
if err != nil {
  panic(err)
}

// Check the results
if results.Passed() {
  fmt.Println("✓ Policy verification passed!")
} else {
  fmt.Println("✗ Policy verification failed")
  // Access detailed failure information from results
}
```

### Verification Workflow

The typical workflow is:

1. **Compile**: Use this framework to compile a PolicySet (resolving remote references, validating structure)
2. **Create Verifier**: Initialize an AMPEL verifier with `verifier.New()`
3. **Verify**: Call `Verify()` with the compiled policy, subject, and options
4. **Process Results**: Check if verification passed and access detailed results

### What AMPEL Does

When you call `Verify()`, AMPEL:
- Gathers attestations for the subject from configured sources
- Validates attestation signatures against expected identities
- Filters attestations by predicate type
- Executes policy tenets (CEL code) against attestation data
- Handles evidence chaining across multiple subjects
- Applies context values to parameterized policies
- Returns structured results indicating pass/fail for each policy/tenet

See the [AMPEL documentation](https://github.com/carabiner-dev/ampel) for complete details on policy evaluation, configuring attestation sources, and working with results.

---

## Performance Considerations

### Parser Performance

- **HJSON vs JSON**: HJSON parsing is slightly slower than JSON due to conversion overhead. For performance-critical applications, use JSON.
- **Signature verification**: Cryptographic operations add overhead. Only enable when needed.
- **Large files**: The parser reads entire files into memory. Very large policies (>10MB) may impact memory usage.

### Compiler Performance

- **Parallel fetching**: Remote references are fetched in parallel, significantly speeding up compilation of PolicySets with many remote policies.
- **Caching**: The storage backend eliminates redundant network requests. Repeated compilations of similar policies are much faster.
- **Recursive depth**: Deep nesting (`MaxRemoteRecursion`) causes exponential growth in fetch operations. Keep policies relatively flat.

### Storage Backend Performance

- **In-memory**: The default `refStore` is fast but not persistent. Content must be re-fetched across compiler instances.
- **Custom backends**: Persistent storage (disk, database) trades speed for durability. Design custom backends carefully to minimize lookup overhead.

### Best Practices

1. **Pin to commit SHAs**: Avoids re-fetching when tags/branches change
2. **Use hash verification**: Enables cache hits even across different URLs
3. **Minimize nesting**: Flatten remote reference hierarchies when possible
4. **Reuse compiler instances**: The storage backend persists across compilations within the same compiler instance
5. **Batch compilations**: If compiling multiple PolicySets that share remote references, use a single compiler instance to maximize cache hits

---

## Next Steps

- **[Policy Materials Reference](policy-materials.md)**: Deep dive into Policy, PolicyGroup, and PolicySet structures
- **[Overview](overview.md)**: High-level introduction to the AMPEL Policy Framework
- **[Protocol Buffer Definitions](../proto/carabiner/policy/v1/policy.proto)**: Complete schema reference
- **[AMPEL Engine](https://github.com/carabiner-dev/ampel)**: Policy evaluation engine documentation
