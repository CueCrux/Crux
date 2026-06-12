# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Homebrew formula TEMPLATE for the cuecrux/tap tap (repo: CueCrux/homebrew-tap,
# creation is an operator action — see ExecPlan decision log).
#
# At release time, scripts/generate-homebrew-formula.sh renders this template:
# {{VERSION}} and the per-artifact {{SHA256_*}} placeholders are filled from
# the release's signed RELEASE-MANIFEST files, then the result is committed to
# the tap. The sha256 values pin the exact artifacts; users who want the full
# cryptographic story verify per docs/verify-release.md.
class Crux < Formula
  desc "Local-first agent memory, retrieval, and signed-receipts daemon"
  homepage "https://github.com/CueCrux/Crux"
  version "{{VERSION}}"
  license "CCL-1.0" # CueCrux Community Licence — source-available

  on_macos do
    on_arm do
      url "https://github.com/CueCrux/Crux/releases/download/v{{VERSION}}/crux-darwin-arm64"
      sha256 "{{SHA256_CRUX_DARWIN_ARM64}}"
    end
    on_intel do
      url "https://github.com/CueCrux/Crux/releases/download/v{{VERSION}}/crux-darwin-amd64"
      sha256 "{{SHA256_CRUX_DARWIN_AMD64}}"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/CueCrux/Crux/releases/download/v{{VERSION}}/crux-linux-amd64"
      sha256 "{{SHA256_CRUX_LINUX_AMD64}}"
    end
  end

  resource "corecruxctl" do
    on_macos do
      on_arm do
        url "https://github.com/CueCrux/Crux/releases/download/v{{VERSION}}/corecruxctl-darwin-arm64"
        sha256 "{{SHA256_CTL_DARWIN_ARM64}}"
      end
      on_intel do
        url "https://github.com/CueCrux/Crux/releases/download/v{{VERSION}}/corecruxctl-darwin-amd64"
        sha256 "{{SHA256_CTL_DARWIN_AMD64}}"
      end
    end
    on_linux do
      on_intel do
        url "https://github.com/CueCrux/Crux/releases/download/v{{VERSION}}/corecruxctl-linux-amd64"
        sha256 "{{SHA256_CTL_LINUX_AMD64}}"
      end
    end
  end

  def install
    binary = Dir["crux-*"].first
    bin.install binary => "crux"
    bin.install_symlink bin/"crux" => "corecruxd"
    resource("corecruxctl").stage do
      ctl = Dir["corecruxctl-*"].first
      bin.install ctl => "corecruxctl"
    end
  end

  service do
    run [opt_bin/"corecruxd"]
    keep_alive successful_exit: false
    environment_variables CORECRUXD_DATA_DIR: var/"crux",
                          CORECRUXD_AUTH_MODE: "dev_scopes",
                          CORECRUXD_UPDATE_CHECK_ENABLED: "0"
    working_dir var/"crux"
  end

  def post_install
    (var/"crux").mkpath
    (var/"crux").chmod 0700
  end

  def caveats
    <<~EOS
      Start the daemon (your explicit action — nothing auto-starts):
        brew services start crux        # or run `crux` directly
      Console:  http://127.0.0.1:14800
      Docs:     https://github.com/CueCrux/Crux/blob/main/docs/getting-started.md
      Verify the artifacts end-to-end (cosign + SLSA):
        https://github.com/CueCrux/Crux/blob/main/docs/verify-release.md
    EOS
  end

  test do
    assert_match "corecruxd", shell_output("#{bin}/crux --version")
  end
end
