# unierp-service-kit

**Layer L1** of the UniERP layered repository architecture
(`PLATFORM_ARCHITECTURE.md` § 4.2).

## Why it is its own repository

Shared service scaffolding — versioning helpers and semver comparison used across the service layer.

## The invariant

A repository may depend only on published artifacts of a strictly lower layer.
Never sideways within a layer. Never upward.

## Extraction status

Extracted from the `ERPSys` monorepo as § 14 Phase 3, with history preserved
via `git-filter-repo`, and packaged so it is genuinely installable: an explicit
`files` allowlist (npm otherwise falls back to `.gitignore` and omits `dist/`),
no `workspace:` specifiers, and a local tsconfig base so it typechecks
standalone.

The monorepo copy remains authoritative until consumers switch.
