// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Interactive prompt UX for `init`. Prompts the operator per profile with
//! a description + recommended-default. TTY detection done by caller.

use dialoguer::{theme::ColorfulTheme, Confirm};

use crux_config_wizard::profile::ProfileFragment;

pub fn prompt_for_profiles(fragments: &[ProfileFragment]) -> std::io::Result<Vec<String>> {
    let theme = ColorfulTheme::default();
    let mut enabled = Vec::new();
    println!("Crux Config Wizard — interactive init");
    println!("Pick which profiles to enable in this workspace.");
    println!();
    for f in fragments {
        let prompt = format!(
            "Enable '{}' (v{}, risk={})?\n  {}",
            f.frontmatter.name, f.frontmatter.version, f.frontmatter.risk_class, f.frontmatter.description
        );
        let yes = Confirm::with_theme(&theme)
            .with_prompt(prompt)
            .default(true)
            .interact()
            .map_err(std::io::Error::other)?;
        if yes {
            enabled.push(f.frontmatter.name.clone());
        }
    }
    Ok(enabled)
}
