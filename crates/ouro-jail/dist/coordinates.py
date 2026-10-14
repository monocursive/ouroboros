"""The current public release coordinates, read from release.json.

release.json is the one place that names the published versions, the Linux
targets and the preview's unsupported clauses; the packaging scripts, the VM
tooling, the website and their tests read it. The archive SHA-256 pins are not
here: they live in the root install.sh's managed pin block, which is the
installer users run; installer_pin() reads one, and bootstrap.py renders them.

This module imports only the standard library, so tooling outside this
directory can load it by path without putting dist/ (and its package.py) on
sys.path.
"""
import json
from pathlib import Path
import re

_RELEASE = json.loads(Path(__file__).with_name('release.json').read_text())
INSTALLER = Path(__file__).resolve().parents[3] / 'install.sh'
PIN_BLOCK = re.compile(r'    # BEGIN SHA256 PINS\n.*?    # END SHA256 PINS\n', re.DOTALL)
PIN_ENTRY = re.compile(r"        ([^:\n]+):([^\n]+)\) expected='([0-9a-f]{64})' ;;\n")

REPOSITORY = _RELEASE['repository']
JAIL_VERSION = _RELEASE['jail']['version']
JAIL_TAG_PREFIX = _RELEASE['jail']['tag_prefix']
PUBLICATION_SCOPE = _RELEASE['jail']['publication_scope']
UNSUPPORTED_CLAUSES = list(_RELEASE['jail']['unsupported_clauses'])
# Release targets with the ELF e_machine their binaries must carry. Only
# Linux: native macOS execution refuses, so no Darwin archive is released.
ELF_MACHINE = dict(_RELEASE['jail']['elf_machine_by_target'])
LINUX_TARGETS = tuple(ELF_MACHINE)
VM_VERSION = _RELEASE['vm']['version']
VM_TAG_PREFIX = _RELEASE['vm']['tag_prefix']
VM_TARGET = _RELEASE['vm']['target']


def jail_tag(version):
    return JAIL_TAG_PREFIX + version


def jail_archive(version, target):
    return f'ouro-jail-{version}-{target}.tar.gz'


def jail_archive_url(version, target):
    return f'https://github.com/{REPOSITORY}/releases/download/{jail_tag(version)}/{jail_archive(version, target)}'


def vm_tag(version):
    return VM_TAG_PREFIX + version


def pin_entries(script):
    """(version, target, sha256) rows of an installer's one managed pin block."""
    blocks = PIN_BLOCK.findall(script)
    if len(blocks) != 1:
        raise ValueError('installer must contain exactly one SHA-256 pin block')
    return PIN_ENTRY.findall(blocks[0])


def installer_pin(version, target):
    """The SHA-256 the public installer pins for one release archive."""
    found = [digest for v, t, digest in pin_entries(INSTALLER.read_text()) if (v, t) == (version, target)]
    if len(found) != 1:
        raise ValueError(f'install.sh must pin {version} for {target} exactly once')
    return found[0]
