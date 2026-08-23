# typed: false
# frozen_string_literal: true

# The Homebrew formula for `ouro`, as a template.
#
# This file is not a formula anybody can install: every placeholder below is filled in by
# `scripts/homebrew-formula.sh <version>`, which reads the digests out of a release's
# SHA256SUMS so that no digest is ever transcribed by hand. The generated file belongs in
# a separate tap repository (`homebrew-ouroboros`), which this project does not create and
# does not publish — see docs/DISTRIBUTION.md for the flow.
#
# WHAT HOMEBREW VERIFIES, AND WHAT IT DOES NOT
#
# Homebrew checks the `sha256` written here against what it downloads, and refuses to
# install on a mismatch. That is a real check, because the digest lives in the tap
# repository and the binary lives on the release host: two places, and an attacker needs
# both. It is not the same check as `ouro update`'s — nothing here verifies the release
# signing key's signature, because Homebrew has no notion of one. A formula is therefore
# as trustworthy as the tap repository's commit history, which is a different and weaker
# statement than "the Ouroboros release key signed this".
#
# There is also no Homebrew bottle. Each asset is already a self-contained binary carrying
# its own OTP release, and a bottle would be a second copy of the same bytes under a
# different digest.
# ---8<--- scripts/homebrew-formula.sh replaces everything above this line ---8<---
class Ouro < Formula
  desc "Terminal client for an Ouroboros runtime"
  homepage "OURO_HOMEPAGE"
  version "OURO_VERSION"
  license "OURO_LICENSE"

  on_macos do
    on_arm do
      url "OURO_BASE_URL/ouro-OURO_VERSION-aarch64-apple-darwin"
      sha256 "OURO_SHA256_AARCH64_APPLE_DARWIN"
    end

    on_intel do
      url "OURO_BASE_URL/ouro-OURO_VERSION-x86_64-apple-darwin"
      sha256 "OURO_SHA256_X86_64_APPLE_DARWIN"
    end
  end

  on_linux do
    on_arm do
      url "OURO_BASE_URL/ouro-OURO_VERSION-aarch64-unknown-linux-gnu"
      sha256 "OURO_SHA256_AARCH64_UNKNOWN_LINUX_GNU"
    end

    on_intel do
      url "OURO_BASE_URL/ouro-OURO_VERSION-x86_64-unknown-linux-gnu"
      sha256 "OURO_SHA256_X86_64_UNKNOWN_LINUX_GNU"
    end
  end

  def install
    # The asset is the executable, named for the platform it can run on. `mix release`
    # bakes the ERTS of the machine that built it, so the Linux assets are Ubuntu 24.04
    # GNU builds rather than static binaries: a distribution with an older glibc needs
    # `make ouro` instead of this formula.
    bin.install Dir["ouro-*"].first => "ouro"
  end

  def caveats
    <<~CAVEATS
      `ouro update` will refuse to replace a Homebrew-installed binary and will tell you
      to use `brew upgrade ouro`, because replacing a file Homebrew owns leaves its
      manifest disagreeing with the disk and the next upgrade silently reverts yours.

      Homebrew checked the SHA-256 recorded in this formula. It did not check the
      Ouroboros release signature — Homebrew has no way to. For that check, install with
      scripts/install.sh on a machine with `minisign`, or verify by hand:

          minisign -V -p dist/release.pub -m SHA256SUMS
    CAVEATS
  end

  test do
    assert_match "ouro #{version}", shell_output("#{bin}/ouro version")
  end
end
