"""The VM tooling names the same releases as dist/release.json."""
from pathlib import Path
import re
import unittest

import cli
import prepare

coordinates = prepare.coordinates


class Coordinates(unittest.TestCase):
    def test_packaged_version_is_the_vm_release(self):
        self.assertEqual(cli.VERSION, coordinates.VM_VERSION)

    def test_preview_readme_names_the_vm_release(self):
        # The DMG carries PREVIEW.txt as its READ-ME.txt, which names the version in its
        # title and in the installed directory it tells users to remove.
        text = Path(__file__).with_name('PREVIEW.txt').read_text()
        named = re.findall(r'\b\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', text)
        self.assertTrue(text.startswith(f'Ouro VM {coordinates.VM_VERSION} '))
        self.assertEqual(set(named), {coordinates.VM_VERSION})

    def test_guest_uses_the_public_linux_release_and_its_installer_pin(self):
        version, target = coordinates.JAIL_VERSION, prepare.JAIL_TARGET
        self.assertTrue(prepare.JAIL_URL.endswith(
            f'/releases/download/{coordinates.jail_tag(version)}/ouro-jail-{version}-{target}.tar.gz'))
        script = coordinates.INSTALLER.read_text()
        self.assertIn(f"        {version}:{target}) expected='{prepare.JAIL_SHA256}' ;;\n", script)


if __name__ == '__main__':
    unittest.main()
