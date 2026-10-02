#!/usr/bin/env python3
"""Install pinned comparison tools into an isolated directory, without root."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

NODE = "24.21.0"
GREYWALL = "0.3.7"
SRT = "0.0.78"
ARTIFACTS = {
    "Linux": (
        f"node-v{NODE}-linux-x64.tar.xz",
        "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6",
        f"greywall_{GREYWALL}_Linux_x86_64.tar.gz",
        "1a340a9027a8ac71a33907f84cb8c39bbaa4a313ef7669ef2bc6f3aaafc5c7ff",
    ),
    "Darwin": (
        f"node-v{NODE}-darwin-arm64.tar.gz",
        "bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057",
        f"greywall_{GREYWALL}_Darwin_arm64.tar.gz",
        "57f29622c47990d8fe7440bed6cf126b29641a564bcf3ebd5f8e90c9e16c235e",
    ),
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    node_archive, node_hash, grey_archive, grey_hash = ARTIFACTS[platform.system()]
    downloads = root / "downloads"
    downloads.mkdir(exist_ok=True)
    artifacts = []
    for name, expected, url, destination in [
        (node_archive, node_hash, f"https://nodejs.org/dist/v{NODE}/{node_archive}", root / "node"),
        (grey_archive, grey_hash, f"https://github.com/GreyhavenHQ/greywall/releases/download/v{GREYWALL}/{grey_archive}", root / "greywall"),
    ]:
        path = downloads / name
        if not path.exists():
            subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error", url, "--output", str(path)], check=True)
        if sha(path) != expected:
            raise SystemExit("checksum mismatch: " + name)
        destination.mkdir(exist_ok=True)
        command = ["tar", "xf", str(path), "-C", str(destination)]
        if destination.name == "node":
            command.append("--strip-components=1")
        subprocess.run(command, check=True)
        artifacts.append({"url": url, "sha256": expected})
    install_home = root / "install-home"
    install_home.mkdir(exist_ok=True)
    package = root / "srt"
    package.mkdir(exist_ok=True)
    env = {"PATH": str(root / "node/bin") + ":/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(install_home), "npm_config_cache": str(root / "npm-cache")}
    subprocess.run([str(root / "node/bin/npm"), "install", "--prefix", str(package), "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", "@anthropic-ai/sandbox-runtime@" + SRT], env=env, check=True)
    lock = package / "package-lock.json"
    manifest = {"schema": "sandbox-comparison-install/1", "versions": {"node": NODE, "greywall": GREYWALL, "srt": SRT}, "artifacts": artifacts, "lock_sha256": sha(lock), "greywall_binary_sha256": sha(root / "greywall/greywall"), "node_binary_sha256": sha(root / "node/bin/node")}
    if platform.system() == "Linux":
        name = "ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz"
        expected = "33e15bcf1624b25cdd2a55813a47a2f95dbe126268203e76aa6a585d1e7b149c"
        url = "https://github.com/BurntSushi/ripgrep/releases/download/15.2.0/" + name
        path = downloads / name
        subprocess.run(["curl", "--fail", "--location", "--silent", "--show-error", url, "--output", str(path)], check=True)
        if sha(path) != expected: raise SystemExit("checksum mismatch: " + name)
        destination = root / "ripgrep"
        destination.mkdir(exist_ok=True)
        subprocess.run(["tar", "xf", str(path), "-C", str(destination), "--strip-components=1"], check=True)
        (root / "bin").mkdir(exist_ok=True)
        import shutil
        shutil.copy2(destination / "rg", root / "bin/rg")
        manifest["artifacts"].append({"url": url, "sha256": expected})
        manifest["versions"]["ripgrep"] = "15.2.0"
    (root / "install.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest), flush=True)


if __name__ == "__main__":
    main()
