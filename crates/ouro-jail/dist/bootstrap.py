"""Render and inspect the public installer's embedded archive SHA-256 pins."""
import re

from package import VERSION

TARGETS = {'x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'}
BLOCK = re.compile(r'    # BEGIN SHA256 PINS\n.*?    # END SHA256 PINS\n', re.DOTALL)
ENTRY = re.compile(r"        ([^:\n]+):([^\n]+)\) expected='([0-9a-f]{64})' ;;\n")


def archive_pins(script):
    blocks = BLOCK.findall(script)
    if len(blocks) != 1:
        raise ValueError('installer must contain exactly one SHA-256 pin block')
    pins = {}
    for version, target, digest in ENTRY.findall(blocks[0]):
        if not VERSION.fullmatch(version) or target not in TARGETS or (version, target) in pins:
            raise ValueError('invalid or duplicate installer SHA-256 pin')
        pins[version, target] = digest
    if not pins:
        raise ValueError('installer has no archive SHA-256 pins')
    return pins


def render_bootstrap(script, version, hashes):
    if not VERSION.fullmatch(version) or set(hashes) != TARGETS:
        raise ValueError('pin a semantic release version and both Linux archives')
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
    script, count = re.subn(r'^    version=[0-9][0-9A-Za-z.+-]*$', lambda _: '    version=' + version,
                            script, flags=re.MULTILINE)
    if count != 1:
        raise ValueError('installer must contain exactly one default release version')
    return script
