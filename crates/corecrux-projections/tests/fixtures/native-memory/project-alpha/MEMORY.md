# Memory Index

## Environment traps

- [Toolchain lives outside PATH](toolchain-outside-path.md) — the linux toolchain EXISTS but is not on PATH; prefix it
- [Shared tree checkout collision](shared-tree-checkout-collision.md) — sibling sessions reset the same nested tree; use a worktree
- [A memory that was deleted](removed-long-ago.md) — index row with no file behind it any more

## Deploy runbooks

- [Host deploy runbook](host-deploy-runbook.md) — ssh, repoint the tag, data-safe volume
- [Handoff bundle](/abs/path/HANDOFF-2026-09-17.md) — absolute path, not a sibling slug

## Odd shapes

- [No frontmatter at all](no-frontmatter.md) — plain prose, no `---` block
- [Missing description](missing-description.md) — frontmatter present, description absent
- [CRLF line endings](crlf-endings.md) — written by a Windows editor
- [Non UTF-8 bytes](non-utf8.md) — one invalid byte in the body
- [Frontmatter never closes](unclosed-frontmatter.md) — opening `---` with no closing `---`
- [Secret shaped token](secret-shaped.md) — quotes a credential-shaped string
