"""Render and inspect the public installer's embedded SHA-256 pins.

The root install.sh carries one managed block of `version:target` pins: the
Linux archives and the macOS VM preview disk image. Rendering keeps every
earlier pin, so the installer still accepts each release it ever named.
"""
import re

from coordinates import LINUX_TARGETS, PIN_BLOCK as BLOCK, VM_TARGET, pin_entries
from package import VERSION

LINUX = set(LINUX_TARGETS)
PIN_TARGETS = LINUX | {VM_TARGET}


def archive_pins(script):
    pins = {}
    for version, target, digest in pin_entries(script):
        if not VERSION.fullmatch(version) or target not in PIN_TARGETS or (version, target) in pins:
            raise ValueError('invalid or duplicate installer SHA-256 pin')
        pins[version, target] = digest
    if not pins:
        raise ValueError('installer has no archive SHA-256 pins')
    return pins


def _render(script, version, hashes, default):
    if not VERSION.fullmatch(version):
        raise ValueError('pin a semantic release version')
    if any(not re.fullmatch('[0-9a-f]{64}', digest) for digest in hashes.values()):
        raise ValueError('invalid archive SHA-256')
    pins = archive_pins(script)
    pins.update(((version, target), digest) for target, digest in hashes.items())
    block = '    # BEGIN SHA256 PINS\n    case "$version:$target" in\n'
    for (release, target), digest in sorted(pins.items()):
        block += f"        {release}:{target}) expected='{digest}' ;;\n"
    block += ('        *) fail "no pinned SHA-256 for $version ($target); download the current installer" ;;\n'
              '    esac\n    # END SHA256 PINS\n')
    script = BLOCK.sub(lambda _: block, script, count=1)
    script, count = re.subn(rf'^    {default}=[0-9][0-9A-Za-z.+-]*$', lambda _: f'    {default}={version}',
                            script, flags=re.MULTILINE)
    if count != 1:
        raise ValueError(f'installer must contain exactly one default {default}')
    return script


def render_bootstrap(script, version, hashes):
    """Pin both Linux archives of a release and make it the Linux default."""
    if set(hashes) != LINUX:
        raise ValueError('pin both Linux archives')
    return _render(script, version, hashes, 'version')


def render_vm_pin(script, version, digest):
    """Pin a macOS VM preview disk image and make it the macOS default."""
    return _render(script, version, {VM_TARGET: digest}, 'macos_version')
