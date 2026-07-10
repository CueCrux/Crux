# vaultcrux-local — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Daemon-local VaultCrux layer: owns VaultCrux classification and content-loading policy
so transport crates (crux-mcp, corecruxd) do not duplicate tier-boundary rules. Two
modules, both policy surfaces.

## Where to start
- `src/tool_surface.rs` — MCP tool tier classification (`ToolTier::Local` vs
  `ToolTier::HostedGated`), the static `TOOL_SURFACE` table, `HOSTED_BACKEND_ID`
- `src/content.rs` — signed content-manifest loading
  (`cuecrux.content.manifest.v1`, CROWN-Ed25519 signatures, BLAKE3 per-file hashes)

## Key symbols
- `tool_tier(name)` / `marker_for_tool(name)` — lookup into `TOOL_SURFACE`;
  unknown names default to `ToolTier::Local` / `"[local]"`
- `load_content_manifest(path, verify_signatures)` — parse + verify → `ContentLoadReport`
- `validate_content_manifest` — schema/signature/file-hash policy checks
- `ContentManifest` / `ContentSignature` — the on-disk manifest contract
  (`CONTENT_MANIFEST_SCHEMA_V1`, `CONTENT_SIGNATURE_ALG`)

## Invariants
- None of I1–I6.

## Test & verify
- `cargo test -p vaultcrux-local`

## Local rules
- The tool/content tier boundary is policy, not a suggestion: consumers must route
  tier decisions through `tool_tier` / `TOOL_SURFACE`, never re-derive them locally.
- Because `tool_tier` defaults unknown names to `Local`, any new hosted-gated MCP tool
  MUST be added to `TOOL_SURFACE` with `ToolTier::HostedGated` — omitting it silently
  under-gates the tool.
- Content manifests that are unsigned or `status: "placeholder"` are rejected when
  signature verification is on (`ContentManifestError` — "unsigned or
  placeholder-signed"). Do not add bypasses for unverified content.
