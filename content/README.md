# Crux Content

This directory holds curated content assets shipped with the daemon.

Content files are licensed under the CueCrux Content Licence v1.0 and are
verified through `content/MANIFEST.json` when `content.manifest_path` is
configured.

The source-tree manifest is a placeholder. With `verify_signatures: true`,
`corecruxd` refuses placeholder or unsigned manifests; release signing must
replace this file before enabling it in production config.
