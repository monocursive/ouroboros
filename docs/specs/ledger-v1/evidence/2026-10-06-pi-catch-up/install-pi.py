"""Install the verified test build without replacing any existing command."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

os.umask(0o022)
revision = "41e6457b009065bd4fe4040b3141da291fb29c9b"
root = Path("/home/monocursive/ouro-pi-41e6457b")
validation = root / "validation"
assert (validation / "validation.exit").read_text().strip() == "0"
doctor = json.loads((validation / "doctor.log").read_text())
assert doctor["ready"] is True
assert doctor["build"]["revision"] == revision
assert doctor["build"]["dirty"] is False
source = Path("/home/monocursive/ouro-ledger-pruning-20261005-pi-r1/target/release")
commands = ["ouro-jail", "ouro-ledger"]
expected = {}
for line in (validation / "binaries.sha256").read_text().splitlines():
    digest, path = line.split(maxsplit=1)
    expected[Path(path).name] = digest
for name in commands:
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == expected[name]

prefix = Path.home() / ".local"
bin_dir = prefix / "bin"
release = prefix / "lib" / "ouroboros" / revision[:8]
for name in commands:
    assert not os.path.lexists(bin_dir / name), f"Existing command: {bin_dir / name}"
assert not os.path.lexists(release), f"Existing release: {release}"
release.mkdir(parents=True)
bin_dir.mkdir(parents=True, exist_ok=True)
for name in commands:
    destination = release / name
    shutil.copyfile(source / name, destination)
    destination.chmod(0o755)
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == expected[name]
manifest = {
    "revision": revision,
    "build_inputs": doctor["build"]["inputs"],
    "target": doctor["build"]["target"],
    "binaries": {name: expected[name] for name in commands},
    "release_directory": str(release),
    "commands": {name: str(bin_dir / name) for name in commands},
}
(release / "installation.json").write_text(json.dumps(manifest, indent=2) + "\n")
for name in commands:
    os.symlink(os.path.relpath(release / name, bin_dir), bin_dir / name)
    result = subprocess.run([str(bin_dir / name), "version", "--json"],
                            check=True, capture_output=True, text=True)
    (validation / f"installed-{name}-version.json").write_text(result.stdout)
(validation / "installation.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest, indent=2))
