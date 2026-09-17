// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Workspace override for the `memory-digest` fragment.
//!
//! ExecPlan `crux-memory-parity-and-codex-bridge-2026-09-17` **M3**.
//!
//! Every other bundled profile is fixed text baked in with `include_str!`. The
//! memory digest is not: its body is the operator's curated engram catalog,
//! rendered by `corecruxctl memory digest` into `.crux/memory-digest.md`. This
//! module swaps that file in as the fragment body when it is present, so the
//! composer, the drift check and the version pins all keep working unchanged.
//!
//! ## Why the wizard re-checks a budget the renderer already enforced
//!
//! The renderer caps the digest, but the file it writes is ordinary text on
//! disk that anything can edit. What the wizard composes goes into the prompt
//! prefix of every Claude Code and Codex session in the workspace, so the last
//! step before that happens re-checks the two properties that make it safe to
//! be there — it is not oversized, and it carries no credential — and falls
//! back to the bundled pointer text rather than composing an override it
//! cannot vouch for. The wizard does this without depending on the daemon
//! crates: both checks are a few lines, and pulling `corecrux-memory` in for
//! them would drag the fact store, billing and sync graphs into a standalone
//! config binary.

use std::path::Path;

use crate::profile::{load_bundled_profiles, ProfileError, ProfileFragment};

/// Workspace-relative path the rendered digest is read from. Mirrors
/// `corecruxctl::memory_distill::DIGEST_FRAGMENT_PATH`.
pub const DIGEST_FRAGMENT_PATH: &str = ".crux/memory-digest.md";

/// Name of the profile this override applies to.
pub const DIGEST_PROFILE: &str = "memory-digest";

/// Token ceiling. Mirrors `corecruxctl::memory_distill::DIGEST_TOKEN_BUDGET`;
/// a digest over it is refused rather than trimmed, because trimming here
/// would produce a body the renderer never hashed.
pub const DIGEST_TOKEN_BUDGET: usize = 2_000;

/// Why a present digest file was not composed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestRejection {
    /// Over [`DIGEST_TOKEN_BUDGET`].
    OverBudget { tokens: usize, budget: usize },
    /// Carried a credential-shaped token.
    CredentialShaped { sample: String },
    /// Present but empty.
    Empty,
}

impl std::fmt::Display for DigestRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverBudget { tokens, budget } => {
                write!(f, "digest is ~{tokens} tokens, over the {budget}-token budget")
            }
            Self::CredentialShaped { sample } => {
                write!(f, "digest contains a credential-shaped token ('{sample}')")
            }
            Self::Empty => write!(f, "digest file is empty"),
        }
    }
}

/// Estimated tokens, `ceil(chars / 4)` — the same estimator the renderer and
/// the recall harness use, so all three quote one number.
pub fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

/// Known credential issuer prefixes. Kept in step with
/// `corecrux_projections::native_memory`'s list.
const SECRET_PREFIXES: &[&str] = &[
    "sk-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "AKIA",
    "ASIA",
    "AIza",
    "base64:",
    "glpat-",
    "npm_",
    "dop_v1_",
    "SG.",
];

/// First credential-shaped token in `text`, if any.
///
/// A credential is a **solid run** of credential characters with at least 12 of
/// them after the issuer prefix. Prose that merely names a prefix — the
/// workspace's own memory says ``the secret is `base64:`-prefixed when
/// re-minting`` — is not one, and swallowing that sentence would gut the entry
/// the digest exists to surface.
pub fn credential_shaped(text: &str) -> Option<String> {
    for raw in text.split_whitespace() {
        let core = raw.trim_matches(|c: char| !c.is_alphanumeric() && !matches!(c, '_' | '-' | '.' | ':'));
        if core.len() < 12 {
            continue;
        }
        if !core
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':' | '+' | '/' | '='))
        {
            continue;
        }
        if SECRET_PREFIXES
            .iter()
            .any(|prefix| core.starts_with(prefix) && core.len() >= prefix.len() + 12)
        {
            return Some(core.to_string());
        }
        if is_jwt_shaped(core) {
            return Some(core.to_string());
        }
    }
    None
}

fn is_jwt_shaped(token: &str) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && token.len() >= 40
        && parts[0].starts_with("ey")
        && parts
            .iter()
            .all(|p| p.len() >= 8 && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

/// Check a candidate digest body. `Ok(body)` is safe to compose.
pub fn vet_digest(body: &str) -> Result<String, DigestRejection> {
    let normalised = if body.contains('\r') {
        body.replace("\r\n", "\n")
    } else {
        body.to_string()
    };
    if normalised.trim().is_empty() {
        return Err(DigestRejection::Empty);
    }
    let tokens = estimate_tokens(&normalised);
    if tokens > DIGEST_TOKEN_BUDGET {
        return Err(DigestRejection::OverBudget {
            tokens,
            budget: DIGEST_TOKEN_BUDGET,
        });
    }
    if let Some(sample) = credential_shaped(&normalised) {
        return Err(DigestRejection::CredentialShaped { sample });
    }
    Ok(normalised.trim_end().to_string() + "\n")
}

/// Read and vet the workspace's rendered digest.
///
/// `Ok(None)` when no digest has been rendered — the ordinary state of a
/// workspace that has not run `corecruxctl memory digest` yet.
pub fn load_digest_body(workspace: &Path) -> Result<Option<String>, DigestRejection> {
    let path = workspace.join(DIGEST_FRAGMENT_PATH);
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    vet_digest(&raw).map(Some)
}

/// Bundled profiles with the `memory-digest` body replaced by the workspace's
/// rendered digest when one is present and vets clean.
///
/// This is the seam every command loads through, so `init`, `regenerate`,
/// `check` and `diff` all agree on what the fragment body is — which is what
/// makes the drift check meaningful rather than a permanent false positive.
pub fn load_workspace_profiles(workspace: &Path) -> Result<Vec<ProfileFragment>, ProfileError> {
    let mut fragments = load_bundled_profiles()?;
    apply_digest_override(&mut fragments, workspace);
    Ok(fragments)
}

/// Apply the override in place; returns the rejection when a present digest was
/// refused, so a caller can surface it.
pub fn apply_digest_override(fragments: &mut [ProfileFragment], workspace: &Path) -> Option<DigestRejection> {
    match load_digest_body(workspace) {
        Ok(Some(body)) => {
            if let Some(fragment) = fragments.iter_mut().find(|f| f.frontmatter.name == DIGEST_PROFILE) {
                fragment.body = body;
            }
            None
        }
        Ok(None) => None,
        Err(rejection) => Some(rejection),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_with(body: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".crux")).unwrap();
        std::fs::write(dir.path().join(DIGEST_FRAGMENT_PATH), body).unwrap();
        dir
    }

    #[test]
    fn missing_digest_leaves_the_bundled_pointer_body() {
        let dir = tempfile::tempdir().unwrap();
        let fragments = load_workspace_profiles(dir.path()).unwrap();
        let digest = fragments
            .iter()
            .find(|f| f.frontmatter.name == DIGEST_PROFILE)
            .expect("bundled");
        assert!(digest.body.contains("corecruxctl memory digest"));
    }

    #[test]
    fn rendered_digest_replaces_the_body() {
        let dir = workspace_with("## Crux Memory Digest\n\n- a-memory — a recall line\n");
        let fragments = load_workspace_profiles(dir.path()).unwrap();
        let digest = fragments
            .iter()
            .find(|f| f.frontmatter.name == DIGEST_PROFILE)
            .expect("bundled");
        assert!(digest.body.contains("- a-memory — a recall line"));
        assert!(!digest.body.contains("corecruxctl memory digest"));
    }

    /// The composed body goes into the prompt prefix of every session in the
    /// workspace, so an oversized file is refused, not trimmed.
    #[test]
    fn oversized_digest_is_refused_and_the_pointer_body_stands() {
        let dir = workspace_with(&"word ".repeat(4_000));
        let mut fragments = load_bundled_profiles().unwrap();
        let rejection = apply_digest_override(&mut fragments, dir.path());
        assert!(matches!(rejection, Some(DigestRejection::OverBudget { .. })));
        let digest = fragments
            .iter()
            .find(|f| f.frontmatter.name == DIGEST_PROFILE)
            .expect("bundled");
        assert!(digest.body.contains("corecruxctl memory digest"));
    }

    #[test]
    fn credential_check_skips_prose_that_merely_names_a_prefix() {
        let prose = "The agent token is the fact plane; the secret is `base64:`-prefixed when re-minting.";
        assert_eq!(credential_shaped(prose), None);
        assert_eq!(
            credential_shaped("leaked glpat-AAAAAAAAAAAAAAAAAAAA here").as_deref(),
            Some("glpat-AAAAAAAAAAAAAAAAAAAA")
        );
        assert!(credential_shaped("ghp_0123456789abcdefghij").is_some());
        // Commit SHAs and slugs must survive: the digest is mostly those.
        assert_eq!(
            credential_shaped("596882cf and wsl-vhdx-never-shrinks-cargo-targets"),
            None
        );
    }

    #[test]
    fn credential_shaped_digest_is_refused() {
        let dir = workspace_with("## Crux Memory Digest\n\n- leaky — token ghp_0123456789abcdefghij\n");
        let mut fragments = load_bundled_profiles().unwrap();
        assert!(matches!(
            apply_digest_override(&mut fragments, dir.path()),
            Some(DigestRejection::CredentialShaped { .. })
        ));
    }

    #[test]
    fn empty_digest_is_refused() {
        let dir = workspace_with("   \n");
        let mut fragments = load_bundled_profiles().unwrap();
        assert!(matches!(
            apply_digest_override(&mut fragments, dir.path()),
            Some(DigestRejection::Empty)
        ));
    }

    /// A CRLF checkout must not change a single byte of what gets composed:
    /// the digest is prompt-prefix content and a line-ending flip would re-bill
    /// the whole prefix.
    #[test]
    fn crlf_digest_normalises_to_the_lf_body() {
        let lf = workspace_with("## Crux Memory Digest\n\n- a-memory — line\n");
        let crlf = workspace_with("## Crux Memory Digest\r\n\r\n- a-memory — line\r\n");
        assert_eq!(
            load_digest_body(lf.path()).unwrap(),
            load_digest_body(crlf.path()).unwrap()
        );
    }
}
