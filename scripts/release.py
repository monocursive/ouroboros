#!/usr/bin/env python3
"""Small, dependency-free release checks shared by local work and GitHub Actions."""
import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NUMBER = r"(0|[1-9][0-9]*)"
TAG = re.compile(rf"v{NUMBER}\.{NUMBER}\.{NUMBER}(-(alpha|beta|rc)\.{NUMBER})?")
TARGETS = (
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu",
)


def check(tag, root=ROOT):
    if not TAG.fullmatch(tag):
        raise ValueError("expected vX.Y.Z or vX.Y.Z-{alpha,beta,rc}.N (no leading zeroes)")
    version = tag[1:]
    mix = re.search(r'^      version: "([^"]+)"', (root / "mix.exs").read_text(), re.M)
    cargo = re.search(r'^version = "([^"]+)"', (root / "tui/Cargo.toml").read_text(), re.M)
    lock = re.search(r'^name = "ouro"\nversion = "([^"]+)"', (root / "tui/Cargo.lock").read_text(), re.M)
    for name, match in (("mix.exs", mix), ("tui/Cargo.toml", cargo), ("tui/Cargo.lock", lock)):
        if not match or match[1] != version:
            raise ValueError(f"{name} must declare version {version}; update versions before tagging")
    return version


def collect(tag, directory, root=ROOT):
    """Only a complete matrix may become a release; never include an old dist/ file."""
    version = check(tag, root)
    names = {f"ouro-{version}-{target}" for target in TARGETS}
    if {p.name for p in directory.iterdir()} != names:
        raise ValueError("expected exactly four native binaries in the release asset directory")
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing, empty or non-regular artifact: {name}")
    shutil.copyfile(root / "install.sh", directory / "install.sh")
    names.add("install.sh")
    lines = []
    for name in sorted(names):
        with (directory / name).open("rb") as stream:
            checksum = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(chunk)
            digest = checksum.hexdigest()
        lines.append(f"{digest}  {name}\n")
    (directory / "SHA256SUMS").write_text("".join(lines))


def releases(history):
    """gh api --paginate writes consecutive JSON arrays, not one outer array."""
    decoder = json.JSONDecoder()
    remaining = history.lstrip()
    if not remaining:
        raise ValueError("empty release history response")
    while remaining:
        page, end = decoder.raw_decode(remaining)
        if not isinstance(page, list):
            raise ValueError("expected an array of releases")
        yield from page
        remaining = remaining[end:].lstrip()


def latest(tag, history):
    if not TAG.fullmatch(tag):
        raise ValueError("invalid release tag")
    history = list(releases(history))
    if "-" in tag:
        return False
    candidate = tuple(map(int, tag[1:].split(".")))
    for release in history:
        other = release["tag_name"]
        if not release["draft"] and not release["prerelease"] and TAG.fullmatch(other) and "-" not in other:
            if tuple(map(int, other[1:].split("."))) > candidate:
                return False
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "collect", "latest", "status"))
    parser.add_argument("tag")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--history", type=Path)
    args = parser.parse_args()
    try:
        if args.command in ("latest", "status"):
            if args.history is None:
                parser.error(f"{args.command} requires --history")
            history = args.history.read_text()
            if args.command == "latest":
                print(str(latest(args.tag, history)).lower())
            else:
                matches = [r for r in releases(history) if r["tag_name"] == args.tag]
                print(("draft" if matches[0]["draft"] else "published") if matches else "missing")
            return
        version = check(args.tag)
        if args.command == "collect":
            if args.directory is None:
                parser.error("collect requires --directory")
            collect(args.tag, args.directory)
        print(version)
    except (ValueError, OSError) as error:
        parser.exit(1, f"release: {error}\n")


if __name__ == "__main__":
    main()
