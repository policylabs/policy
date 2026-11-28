# Policy Materials Reference

This document provides an in-depth reference for the three policy material elements: **Policy**, **PolicyGroup**, and **PolicySet**.

## Table of Contents

- [Policy](#policy)
  - [Policy Metadata](#policy-metadata)
  - [Expected Identities](#expected-identities)
  - [Tenets](#tenets)
  - [Context Values](#context-values)
  - [Applicability Conditions](#applicability-conditions)
  - [Evidence Chains](#evidence-chains)
  - [Predicates](#predicates)
  - [Transformers](#transformers)
- [PolicyGroup](#policygroup)
  - [PolicyGroup Metadata](#policygroup-metadata)
  - [PolicyBlocks](#policyblocks)
- [PolicySet](#policyset)
  - [PolicySet Metadata](#policyset-metadata)
  - [Common Elements](#common-elements)
  - [Evidence Chains in PolicySets](#evidence-chains-in-policysets)
- [Remote Referencing](#remote-referencing)
  - [Reference Syntax](#reference-syntax)
  - [Supported Locations](#supported-locations)
  - [Self References](#self-references)
  - [Integrity Verification](#integrity-verification)
- [Complete Examples](#complete-examples)

---

## Policy

A **Policy** is the fundamental evaluation unit. It contains one or more **tenets** (executable checks) that are evaluated against attestations to verify software artifacts meet specific requirements.

### Basic Structure

```json
{
  "id": "sbom-license-check",
  "meta": {
    "description": "Verify SBOM contains only approved licenses",
    "runtime": "cel@v0",
    "assert_mode": "AND",
    "enforce": "ON"
  },
  "identities": [...],
  "context": {...},
  "tenets": [...]
}
```

### Policy Metadata

The `meta` field contains information about the policy itself:

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `runtime` | string | Runtime for executing tenet code (e.g., `cel@v0`) | `cel@v0` |
| `name` | string | Human-readable name of the policy. Must be a single line. | - |
| `description` | string | Human-readable description of what the policy checks | - |
| `assert_mode` | string | How tenets are evaluated: `AND` (all must pass) or `OR` (at least one must pass) | `AND` |
| `enforce` | string | Enforcement mode: `ON` (failures fail parent) or `OFF` (failures are warnings) | `ON` |
| `version` | int64 | Policy version number | - |
| `expiration` | timestamp | Optional expiration date for the policy | - |
| `controls` | array | Security framework controls this policy addresses (see [Controls](#security-framework-controls)) | - |
| `origin` | ResourceDescriptor | Source information (populated by parser/compiler) | - |

#### Assert Modes

The `assert_mode` controls how tenets are evaluated:

- **`AND`** (default): ALL tenets must pass for the policy to pass
- **`OR`**: At least ONE tenet must pass for the policy to pass

Example use cases:
- `AND`: "Check that SBOM exists AND contains no GPL licenses AND is properly signed"
- `OR`: "Verify signature with key A OR key B OR key C"

#### Enforce Modes

The `enforce` field determines what happens when a policy fails:

- **`ON`** (default): Policy failures cause the parent PolicySet evaluation to fail
- **`OFF`**: Policy is still evaluated, but failures are treated as warnings and don't fail the PolicySet

This is useful for:
- Gradual rollout of new policies (enforce OFF initially, gather data, then switch to ON)
- Non-blocking checks that inform but don't block
- Policies under development or testing

#### Security Framework Controls

The `controls` array maps policies to security framework requirements (NIST, CIS, etc.):

```json
{
  "controls": [
    {
      "id": "SA-10",
      "framework": "nist-ssdf",
      "title": "Developer Security Testing",
      "class": "practices"
    }
  ]
}
```

This enables:
- Compliance reporting (which policies map to which controls)
- Framework-based policy organization
- Audit trail for security certifications

### Expected Identities

Identities define **who should sign the attestations** being evaluated (not the policy files themselves). When AMPEL evaluates a policy, it verifies that attestation signatures match the expected identities.

#### Identity Types

**1. Sigstore Identity**

For attestations signed with [Sigstore](https://www.sigstore.dev/):

```json
{
  "id": "trusted-builder",
  "sigstore": {
    "issuer": "https://token.actions.githubusercontent.com",
    "identity": "https://github.com/myorg/myrepo/.github/workflows/build.yml@refs/heads/main",
    "mode": "exact"
  }
}
```

Fields:
- `issuer`: OIDC issuer URL from the Fulcio certificate
- `identity`: Subject (email or workflow identity) from the certificate
- `mode`: Matching mode - `exact` (default) or `regexp` for pattern matching

**2. Key Identity**

For attestations signed with traditional public keys:

```json
{
  "id": "build-key",
  "key": {
    "id": "key-2024-01",
    "type": "pgp",
    "data": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."
  }
}
```

**3. Identity Reference**

Reference an identity defined elsewhere (typically in `PolicySet.common.identities`):

```json
{
  "id": "org-identity",
  "ref": {
    "id": "organization-build-identity"
  }
}
```

This enables identity reuse across multiple policies.

#### Using Identities

Identities can be defined:
1. **Directly in a Policy**: Used only by that policy
2. **In PolicySet.common.identities**: Shared across all policies via IdentityRef
3. **In Chain Links**: For verifying specific links in an evidence chain

### Tenets

**Tenets** are the individual checks that make up a policy. Each tenet contains executable code that evaluates attestation data and returns a pass/fail result.

```json
{
  "tenets": [
    {
      "id": "check-license",
      "title": "Verify only approved licenses",
      "runtime": "cel@v0",
      "code": "has(sbom.packages) && sbom.packages.all(p, p.licenseConcluded in allowed_licenses)",
      "predicates": {
        "types": ["https://spdx.dev/Document"]
      },
      "error": {
        "message": "SBOM contains unapproved licenses",
        "guidance": "Review the licenses in your dependencies and remove any that are not in the approved list"
      }
    }
  ]
}
```

#### Tenet Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier for the tenet |
| `title` | string | Human-readable description |
| `runtime` | string | Runtime for executing code (default: `cel@v0`) |
| `code` | string | Executable code that performs the check |
| `predicates` | PredicateSpec | Filter which attestations this tenet evaluates |
| `outputs` | map | Named outputs that can be used by other tenets |
| `error` | Error | Error message and guidance when the tenet fails |
| `assessment` | Assessment | Custom assessment message |

#### Runtimes

Tenets support multiple runtime environments for executing code:

**CEL (Common Expression Language)** - Default runtime specified as `cel@v0`:

```json
{
  "runtime": "cel@v0",
  "code": "sbom.packages.size() > 0"
}
```

CEL is a non-Turing complete expression language designed for safe policy evaluation. It's the default and recommended runtime.

**Future Runtimes**: Support for Rego (`rego@v1`) and Cedar (`cedar@v1`) is planned.

If `runtime` is omitted on a tenet, it inherits from the policy-level `meta.runtime`, which defaults to `cel@v0`.

#### Predicate Specification

The `predicates` field filters which attestations are evaluated by this tenet:

```json
{
  "predicates": {
    "types": [
      "https://spdx.dev/Document",
      "https://cyclonedx.org/schema"
    ],
    "limit": 1
  }
}
```

- `types`: Array of predicate type URIs (only attestations with matching predicate types are evaluated)
- `limit`: Maximum number of attestations to evaluate (0 or omitted = evaluate all matching)

This is useful for:
- Processing only SBOM attestations: `["https://spdx.dev/Document"]`
- Processing only provenance: `["https://slsa.dev/provenance/v1"]`
- Requiring exactly one attestation: `"limit": 1`

#### Error Handling

The `error` field provides user feedback when a tenet fails:

```json
{
  "error": {
    "message": "Required SBOM not found",
    "guidance": "Ensure your build process generates an SBOM and attaches it as an attestation"
  }
}
```

- `message`: Brief description of what failed
- `guidance`: Actionable steps to fix the issue

#### Outputs

Tenets can produce named outputs that other tenets can reference:

```json
{
  "id": "extract-version",
  "code": "sbom.version",
  "outputs": {
    "sbom_version": {
      "code": "sbom.version"
    }
  }
}
```

This enables:
- Extracting data for use in subsequent checks
- Building complex multi-stage evaluations
- Sharing computed values across tenets

### Context Values

**Context values** enable policy reuse by parameterizing policies. They are declared in the policy definition and provided at runtime when invoking AMPEL.

```json
{
  "context": {
    "allowed_licenses": {
      "type": "array",
      "required": true,
      "description": "List of approved SPDX license identifiers",
      "default": ["MIT", "Apache-2.0", "BSD-3-Clause"]
    },
    "max_critical_vulns": {
      "type": "number",
      "required": false,
      "default": 0,
      "description": "Maximum number of critical vulnerabilities allowed"
    }
  }
}
```

#### Context Value Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Value type: `string`, `number`, `boolean`, `array`, `object` |
| `required` | boolean | Whether this value must be provided at runtime |
| `default` | any | Default value if not provided at runtime |
| `description` | string | Human-readable description |

#### Providing Context Values

When running AMPEL, context values can be provided via:
- **Command-line flags**: `--context allowed_licenses=MIT,Apache-2.0`
- **Environment variables**: `POLICY_CONTEXT_ALLOWED_LICENSES=MIT,Apache-2.0`
- **JSON files**: `--context-file context.json`

See the [AMPEL documentation](https://github.com/carabiner-dev/ampel) for details.

#### Use Cases

Context values enable powerful policy patterns:
- **License checking**: Single policy, different allowed licenses per organization
- **Threshold policies**: Same vulnerability policy, different thresholds per project
- **Environment-specific checks**: Different requirements for dev vs. prod
- **Dynamic configuration**: Policies adapt to runtime conditions

### Applicability Conditions

A policy may declare a `when` condition that gates its evaluation. The
condition is an expression evaluated **before any evidence is fetched**,
against the subject under evaluation, the context values in scope and the
runtime plugins; predicates are not available to it. When it yields `false`
the policy is **skipped**: its result carries the status `SKIPPED`, records the
condition, and does not count towards the status of its PolicySet or block.
An absent `when`, or one with an empty expression, means the policy always
evaluates.

```json
{
    "id": "slsa-v1-provenance",
    "when": {
        "expression": "semver.satisfies(context.drop_version, '>=2.0.0')"
    },
    "context": {
        "drop_version": { "type": "string", "required": true }
    },
    "tenets": [ ... ]
}
```

#### When Fields

| Field | Type | Description |
|-------|------|-------------|
| `expression` | string | Evaluator-language snippet that must yield a boolean. Empty means the policy always evaluates. |
| `runtime` | string | Evaluator used for the expression. Defaults to the runtime of the policy, or of its parent when the policy defines none. Only valid together with `expression`. |

Every context value the expression reads **must be declared**, either in the
policy's own `context` block or in the `common.context` of the PolicySet or
PolicyGroup it belongs to. Only declared values are exposed to the runtime, so
an expression reading an undeclared one fails when the condition is
evaluated.

Conditions exist so one policy set can hold releases to what they shipped:
old releases are checked against the attestations they carry, new ones
against a stricter bar, and the policies themselves stay reusable because
the condition lives outside their tenets. `when` is also accepted on
[PolicyBlocks](#policyblocks), where it skips the whole block. PolicySets and
PolicyGroups are containers and carry no condition of their own; gate the
policies and blocks inside them instead.

### Evidence Chains

Evidence chains connect attestations with different subjects, allowing policies to evaluate evidence across related artifacts.

**Problem**: You're verifying a container image (hash: `abc123`), but build provenance exists in attestations about the git commit (hash: `def456`) it was built from.

**Solution**: Define a chain that extracts the commit hash from the image's SLSA provenance, then evaluates policies using attestations about that commit.

```json
{
  "chain": [
    {
      "predicate": {
        "type": "https://slsa.dev/provenance/v1",
        "runtime": "cel@v0",
        "selector": "materials.filter(m, m.uri.startsWith('git+')).first().digest.sha1",
        "identities": [...]
      }
    }
  ]
}
```

#### ChainedPredicate Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Predicate type to look for in attestations |
| `selector` | string | Code to extract the next subject from the predicate |
| `runtime` | string | Runtime for executing the selector (e.g., `cel@v0`) |
| `identities` | array | Expected signers for this chain link |

#### How Chains Work

1. Start with the initial subject (e.g., container image hash)
2. Find attestations for that subject matching the predicate type
3. Execute the selector on the predicate to extract the next subject
4. Find attestations for the new subject
5. Evaluate policies using those attestations
6. Repeat for additional chain links

This enables:
- Tracing from artifacts back to source code
- Following build → image → deployment chains
- Verifying multi-stage processes

### Predicates

The `predicates` field at the policy level specifies which attestation types the entire policy should process:

```json
{
  "predicates": {
    "types": ["https://spdx.dev/Document"],
    "limit": 1
  }
}
```

This filters attestations before any tenets are evaluated, ensuring the policy only processes relevant evidence.

### Transformers

**Note**: Transformers are available as an **early preview implementation**. The API may change in future versions.

Transformers modify or enrich attestation data before evaluation:

```json
{
  "transformers": [
    {
      "id": "normalize-sbom"
    }
  ]
}
```

Transformers enable:
- Normalizing different SBOM formats (SPDX, CycloneDX) to a common structure
- Enriching data with external information
- Pre-processing complex attestations

The transformer implementation is functional but the interface is subject to change.

---

## PolicyGroup

A **PolicyGroup** models complex security controls by organizing policies into blocks with different evaluation strategies. Groups act as atomic units at the PolicySet level.

### Basic Structure

```json
{
  "id": "secure-build-control",
  "meta": {
    "description": "Comprehensive secure build verification"
  },
  "blocks": [
    {
      "id": "provenance-verification",
      "meta": {
        "description": "Verify build provenance",
        "assert_mode": "AND"
      },
      "policies": [...]
    },
    {
      "id": "alternative-signatures",
      "meta": {
        "description": "Accept any trusted signature",
        "assert_mode": "OR"
      },
      "policies": [...]
    }
  ]
}
```

### PolicyGroup Metadata

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `name` | string | Human-readable name of the group. Must be a single line. | - |
| `description` | string | Human-readable description | - |
| `version` | int64 | Group version number | - |
| `controls` | array | Security framework controls | - |
| `enforce` | string | Enforcement mode: `ON` or `OFF` | `ON` |
| `expiration` | timestamp | Optional expiration date | - |
| `origin` | ResourceDescriptor | Source information | - |

The `enforce` mode works the same as for policies: `OFF` means group failures don't fail the PolicySet.

### PolicyBlocks

**PolicyBlocks** group policies and apply a specific evaluation strategy:

```json
{
  "id": "slsa-checks",
  "meta": {
    "description": "SLSA provenance requirements",
    "assert_mode": "AND",
    "enforce": "ON",
    "controls": [...]
  },
  "policies": [
    {
      "id": "slsa-level-2",
      "tenets": [...]
    },
    {
      "id": "trusted-builder",
      "tenets": [...]
    }
  ]
}
```

#### Block Metadata

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `description` | string | Block description | - |
| `assert_mode` | string | Evaluation mode: `AND` or `OR` | `AND` |
| `enforce` | string | Enforcement mode: `ON` or `OFF` | `ON` |
| `controls` | array | Framework controls | - |

#### Block Assert Modes

The `assert_mode` controls how policies within the block are evaluated:

- **`AND`**: ALL policies in the block must pass for the block to pass
- **`OR`**: At least ONE policy in the block must pass for the block to pass

#### Group Evaluation Logic

A **PolicyGroup passes** when **ALL its blocks pass**.

This enables sophisticated requirements modeling:

```json
{
  "blocks": [
    {
      "id": "required-checks",
      "meta": { "assert_mode": "AND" },
      "policies": [
        // ALL of these must pass
      ]
    },
    {
      "id": "alternative-checks",
      "meta": { "assert_mode": "OR" },
      "policies": [
        // At least ONE of these must pass
      ]
    }
  ]
}
```

**Result**: The group passes if (all required checks pass) AND (at least one alternative passes).

### Conditions on Blocks

Each PolicyBlock accepts a `when` condition with the same shape and rules as a
policy's (see [Applicability Conditions](#applicability-conditions)). A
skipped block is reported as `SKIPPED` and does not take part in the group's
assert mode. Context values read by a block's condition must be declared in
the group's `common.context` or inherited from the PolicySet. The group
itself carries no condition: it is a container for its blocks.

### When to Use PolicyGroups

Use **PolicyGroups** instead of direct policies when:

1. **Multiple evaluation strategies**: You need some policies to use AND and others to use OR
2. **Complex controls**: Modeling security frameworks with multi-part requirements
3. **Alternative paths**: Multiple ways to achieve compliance
4. **Logical organization**: Grouping related policies for clarity

Use **direct policies** in a PolicySet when:
- All policies must simply pass (flat AND)
- Policies are independent and don't require grouping
- Simple, straightforward requirements

---

## PolicySet

A **PolicySet** is the top-level container that brings policies and groups together. It's what you load and execute with AMPEL.

### Basic Structure

```json
{
  "id": "organization-policy",
  "meta": {
    "description": "Complete organizational security policy",
    "runtime": "cel@v0"
  },
  "common": {
    "identities": [...],
    "context": {...}
  },
  "policies": [...],
  "groups": [...],
  "chain": [...]
}
```

### PolicySet Metadata

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `runtime` | string | Default runtime for all policies | `cel@v0` |
| `name` | string | Human-readable name of the set. Must be a single line. | - |
| `description` | string | PolicySet description | - |
| `version` | int64 | PolicySet version | - |
| `enforce` | string | Enforcement mode: `ON` or `OFF` | `ON` |
| `expiration` | timestamp | Optional expiration date | - |
| `frameworks` | array | Referenced security frameworks | - |
| `origin` | ResourceDescriptor | Source information | - |

#### Framework References

The `frameworks` array documents which security frameworks this PolicySet addresses:

```json
{
  "frameworks": [
    {
      "id": "nist-ssdf",
      "name": "NIST Secure Software Development Framework",
      "definition": {
        "uri": "https://csrc.nist.gov/Projects/ssdf",
        "digest": {...}
      }
    }
  ]
}
```

This enables:
- Compliance reporting and mapping
- Framework-based policy organization
- Audit documentation

### Common Elements

The `common` section defines elements shared across all policies in the set:

```json
{
  "common": {
    "identities": [
      {
        "id": "org-builder",
        "sigstore": {
          "issuer": "https://token.actions.githubusercontent.com",
          "identity": "https://github.com/myorg/*",
          "mode": "regexp"
        }
      }
    ],
    "context": {
      "organization": {
        "type": "string",
        "required": true,
        "description": "Organization name"
      }
    }
  }
}
```

#### Shared Identities

Identities defined in `common.identities` can be referenced by any policy using an IdentityRef:

```json
{
  "policies": [
    {
      "identities": [
        {
          "ref": { "id": "org-builder" }
        }
      ]
    }
  ]
}
```

This enables:
- Single source of truth for organizational identities
- Easy updates (change once, affects all policies)
- Consistent identity requirements

#### Shared Context

Context values in `common.context` are available to all policies. Policies can also define their own context values, which are merged with the common ones.

### Evidence Chains in PolicySets

Chains defined at the PolicySet level apply to all policies:

```json
{
  "chain": [
    {
      "predicate": {
        "type": "https://slsa.dev/provenance/v1",
        "selector": "materials[0].digest.sha1",
        "runtime": "cel@v0"
      }
    }
  ]
}
```

This enables:
- Following evidence chains across the entire policy evaluation
- Consistent subject chaining for all policies
- Complex multi-artifact verification scenarios

### Policies vs. Groups in a PolicySet

A PolicySet can contain:
- **Policies**: Direct policy definitions or remote references
- **Groups**: PolicyGroup definitions or remote references

Or both!

```json
{
  "policies": [
    {
      "id": "simple-check",
      "tenets": [...]
    },
    {
      "source": {
        "location": {
          "uri": "git+https://github.com/org/policies@sha#common/sbom-check.json"
        }
      }
    }
  ],
  "groups": [
    {
      "id": "complex-control",
      "blocks": [...]
    }
  ]
}
```

**Evaluation**: ALL policies must pass AND ALL groups must pass for the PolicySet to pass (unless `enforce: OFF` is set on specific elements).

---

## Remote Referencing

Remote referencing enables distributed policy management by allowing policies, groups, and even entire PolicySets to be stored remotely and referenced by URI.

### Why Remote References?

- **Centralized management**: Store organizational policies in a git repository
- **Version control**: Pin to specific commits, use tags for versions
- **Reusability**: Share common policies across teams and projects
- **Separation of concerns**: Policy authors vs. policy users
- **Integrity**: Verify content hasn't been tampered with using hashes

### Reference Syntax

A reference specifies where to fetch the remote content:

```json
{
  "source": {
    "location": {
      "uri": "git+https://github.com/org/policies@9a70ca49804c2b993bb6b62d51d5524f3443d6ec#path/to/policy.json"
    }
  }
}
```

or with integrity verification:

```json
{
  "source": {
    "location": {
      "uri": "https://policies.example.com/sbom-check.json",
      "digest": {
        "sha256": "abc123..."
      }
    }
  }
}
```

### Supported Locations

#### Git Repositories (VCS Locators)

**HTTPS**:
```
git+https://github.com/org/repo@commit-sha#path/to/file.json
git+https://github.com/org/repo@v1.2.3#path/to/file.json
```

**SSH**:
```
git+ssh://git@github.com/org/repo@commit-sha#path/to/file.json
```

Format: `git+{protocol}://{host}/{org}/{repo}@{ref}#{path}`

- `protocol`: `https` or `ssh`
- `ref`: Commit SHA, tag, or branch name (SHAs recommended for pinning)
- `path`: Path to the file within the repository

#### HTTPS URLs

```
https://policies.example.com/policies/sbom-check.json
https://cdn.example.com/policies/v1/build-provenance.json
```

Any HTTPS URL that returns policy JSON.

### Self References

A reference whose `uri` starts with `$/` points to a file in the same repository, at the same revision, as the document it is written in. What follows `$/` is the path of the file from the root of the repository:

```json
{
  "source": {
    "location": {
      "uri": "$/slsa/slsa-builder-id.json"
    }
  }
}
```

A self reference names no repository and no revision. It takes both from its document, so a PolicySet and the policies it is made of always come from one revision and can be changed in a single commit. The notation follows the [self repository syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) of GitHub Actions.

Where a self reference is read from depends on where its document was read from:

| The document was read from | `$/path` is read from |
|----------------------------|------------------------|
| A VCS locator, such as `git+https://github.com/org/repo@sha#sets/set.json` | The same repository at the same commit: `git+https://github.com/org/repo@sha#path` |
| A local file | The file at `path` in the working tree of the git repository the file is in, committed or not, with no network access |
| An HTTPS URL | Nowhere: the compile fails, a URL has no revision to read the reference at |

Rules:

- The path is counted from the root of the repository, never from the directory of the document. It cannot leave the repository: `..`, `.` and empty elements are refused, and so is a symbolic link pointing outside of it.
- A self reference takes no revision. `$/policy.json@v1` is an error.
- It is written in `uri`. The compiler fills `downloadLocation` in with what the reference resolved to and ignores a value written there.
- A self reference resolves against the document it is written in, not against the document that referenced that one. A group fetched from another repository reads its self references from that repository.
- A locator that names a branch, a tag or no revision is resolved to a commit before the document is read, and its self references are read at that commit.
- A self reference counts as pinned without a `digest`: it is as pinned as its document. A `digest` can still be added and is verified.

When a document is compiled from a local file, the policies inlined from self references record `$/path` and their digest as their origin, with no commit, so compiling the same tree always produces the same output.

A document handed to the compiler as data has no location. Tell the compiler where it came from, see [Compiling from Various Sources](tooling.md#compiling-from-various-sources).

### Integrity Verification

Add a `digest` to verify the fetched content matches expected hashes:

```json
{
  "source": {
    "location": {
      "uri": "https://example.com/policy.json",
      "digest": {
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha512": "cf83e1357eefb8bd..."
      }
    }
  }
}
```

The compiler will:
1. Fetch the content
2. Compute its hash(es)
3. Compare against provided digests
4. Fail if hashes don't match

Supported algorithms: `sha256`, `sha512`, and others from the [in-toto spec](https://github.com/in-toto/attestation/tree/main/spec/v1).

### Referencing Different Elements

**Policy Reference**:
```json
{
  "policies": [
    {
      "source": {
        "location": {
          "uri": "git+https://github.com/org/policies@sha#policies/sbom.json"
        }
      }
    }
  ]
}
```

**PolicyGroup Reference**:
```json
{
  "groups": [
    {
      "source": {
        "location": {
          "uri": "git+https://github.com/org/policies@sha#groups/build-controls.json"
        }
      }
    }
  ]
}
```

**Nested References**: Remote policies can themselves reference other remote policies! The compiler handles recursive fetching up to a configurable depth (default: 3 levels).

### Gating Referenced Policies

A `when` condition set on the stanza that references a policy is applied to
the assembled policy, exactly like `identities`, `context` or `meta`
overlays. This is how a library policy is reused with a condition without
editing it:

```json
{
    "policies": [
        {
            "id": "provenance-current",
            "source": { "location": { "uri": "git+https://github.com/carabiner-dev/policies@<commit>#slsa/has-attestation.json" } },
            "when": { "expression": "semver.satisfies(context.drop_version, '>=2.0.0')" }
        },
        {
            "id": "provenance-legacy",
            "source": { "location": { "uri": "git+https://github.com/carabiner-dev/policies@<commit>#slsa/has-attestation.json" } },
            "predicates": { "types": ["https://slsa.dev/provenance/v0.2"] },
            "when": { "expression": "semver.satisfies(context.drop_version, '<2.0.0')" }
        }
    ]
}
```

The same applies to a local PolicyBlock that shares its id with a block of a
referenced group: the remote block's contents are merged in and the local
condition gates the result.

### How Remote Referencing Works

When the compiler encounters a reference:

1. **Extract**: Identify all remote references in the policy structure
2. **Fetch**: Download content from remote locations (in parallel for performance)
3. **Cache**: Store fetched content in the storage backend
4. **Parse**: Parse the remote content as a policy/group/set
5. **Assemble**: Replace the reference with the actual policy content
6. **Validate**: Verify the assembled structure is valid

The storage backend acts as a cache, so if the same content is referenced multiple times (same URI or same hash), it's only fetched once.

### Reference Identifiers

References can include an `id` to help locate policies:

```json
{
  "source": {
    "id": "sbom-license-check",
    "location": {
      "uri": "git+https://github.com/org/policies@sha#policies/sbom.json"
    }
  }
}
```

The storage backend indexes by:
- Content hash (SHA-256)
- Source URI
- Policy ID

This enables efficient lookups and deduplication.

### Security Considerations

**Always pin to commit SHAs** when using git references:
- ✅ Good: `@9a70ca49804c2b993bb6b62d51d5524f3443d6ec`
- ❌ Bad: `@main` (can change, not reproducible)
- ⚠️ Acceptable: `@v1.2.3` (tags can be moved, but generally stable)

**Use digest verification** for HTTPS URLs:
- Without digests, you trust the server not to change content
- With digests, you have cryptographic proof of integrity

**Consider signature verification**: While not yet fully implemented, policy signature verification will provide additional assurance that policies come from trusted authors.

---

## Complete Examples

### Example 1: Simple SBOM Policy

```json
{
  "id": "sbom-exists",
  "meta": {
    "description": "Verify an SBOM attestation exists",
    "assert_mode": "AND",
    "enforce": "ON"
  },
  "tenets": [
    {
      "id": "has-sbom",
      "title": "SBOM attestation exists",
      "runtime": "cel@v0",
      "code": "has(sbom.packages) && sbom.packages.size() > 0",
      "predicates": {
        "types": ["https://spdx.dev/Document"],
        "limit": 1
      },
      "error": {
        "message": "No SBOM found",
        "guidance": "Ensure your build process generates an SBOM"
      }
    }
  ]
}
```

### Example 2: Policy with Context Values

```json
{
  "id": "license-check",
  "meta": {
    "description": "Verify only approved licenses are used"
  },
  "context": {
    "allowed_licenses": {
      "type": "array",
      "required": true,
      "description": "SPDX license identifiers to allow"
    }
  },
  "tenets": [
    {
      "id": "check-licenses",
      "code": "sbom.packages.all(pkg, pkg.licenseConcluded in allowed_licenses)",
      "predicates": {
        "types": ["https://spdx.dev/Document"]
      }
    }
  ]
}
```

### Example 3: PolicyGroup with Multiple Blocks

```json
{
  "id": "build-verification",
  "meta": {
    "description": "Comprehensive build verification"
  },
  "blocks": [
    {
      "id": "required-provenance",
      "meta": {
        "description": "Required provenance checks",
        "assert_mode": "AND"
      },
      "policies": [
        {
          "id": "slsa-present",
          "tenets": [
            {
              "code": "has(slsa.buildType)",
              "predicates": {
                "types": ["https://slsa.dev/provenance/v1"]
              }
            }
          ]
        },
        {
          "id": "reproducible",
          "tenets": [
            {
              "code": "slsa.buildConfig.reproducible == true"
            }
          ]
        }
      ]
    },
    {
      "id": "signature-verification",
      "meta": {
        "description": "Accept any trusted signature",
        "assert_mode": "OR"
      },
      "policies": [
        {
          "id": "github-actions",
          "identities": [
            {
              "sigstore": {
                "issuer": "https://token.actions.githubusercontent.com",
                "identity": "https://github.com/myorg/.*",
                "mode": "regexp"
              }
            }
          ],
          "tenets": [{"code": "true"}]
        },
        {
          "id": "jenkins-key",
          "identities": [
            {
              "key": {
                "id": "jenkins-2024",
                "type": "pgp",
                "data": "..."
              }
            }
          ],
          "tenets": [{"code": "true"}]
        }
      ]
    }
  ]
}
```

### Example 4: PolicySet with Remote References

```json
{
  "id": "org-policy-v1",
  "meta": {
    "description": "Organization-wide security policy",
    "version": 1
  },
  "common": {
    "identities": [
      {
        "id": "org-builder",
        "sigstore": {
          "issuer": "https://token.actions.githubusercontent.com",
          "identity": "https://github.com/myorg/.*",
          "mode": "regexp"
        }
      }
    ],
    "context": {
      "organization": {
        "type": "string",
        "default": "MyOrg"
      }
    }
  },
  "policies": [
    {
      "source": {
        "location": {
          "uri": "git+https://github.com/myorg/policies@9a70ca49804c2b993bb6b62d51d5524f3443d6ec#common/sbom-exists.json"
        }
      }
    },
    {
      "id": "custom-check",
      "tenets": [...]
    }
  ],
  "groups": [
    {
      "source": {
        "location": {
          "uri": "git+https://github.com/myorg/policies@9a70ca49804c2b993bb6b62d51d5524f3443d6ec#groups/slsa-verification.json"
        }
      }
    }
  ]
}
```

---

## Next Steps

- **[Tooling Reference](tooling.md)**: Deep dive into the Parser, Compiler, and Storage Backend
- **[Protocol Buffer Definitions](../proto/carabiner/policy/v1/policy.proto)**: Complete schema reference
- **[AMPEL Engine](https://github.com/carabiner-dev/ampel)**: Policy evaluation engine documentation
