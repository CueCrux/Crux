## Summary
<!-- What does this PR do? -->

## Type
- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring
- [ ] Documentation
- [ ] Test coverage

## Checklist
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace` passes (no new warnings)
- [ ] `cargo test --workspace` passes
- [ ] Coverage does not decrease
- [ ] CHANGELOG.md updated (if user-facing change)
- [ ] Documentation updated (if API change)

## Integration Packs
<!-- Complete this section if the PR adds or changes files under integrations/community/. -->
- [ ] Pack manifest uses `crux.integration.v1`
- [ ] Manifest hash and Ed25519 Passport signature are included
- [ ] Pack is declarative-only; no `external_helper`
- [ ] Capabilities, network hosts, and data access are documented in the pack README
- [ ] Dangerous capabilities include maintainer-approved `review.json`
