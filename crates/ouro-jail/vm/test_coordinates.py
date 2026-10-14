"""The VM tooling names the same releases as dist/release.json."""
import unittest

import cli
import prepare

coordinates = prepare.coordinates


class Coordinates(unittest.TestCase):
    def test_packaged_version_is_the_vm_release(self):
        self.assertEqual(cli.VERSION, coordinates.VM_VERSION)

    def test_guest_uses_the_public_linux_release_and_its_installer_pin(self):
        version, target = coordinates.JAIL_VERSION, prepare.JAIL_TARGET
        self.assertTrue(prepare.JAIL_URL.endswith(
            f'/releases/download/{coordinates.jail_tag(version)}/ouro-jail-{version}-{target}.tar.gz'))
        script = coordinates.INSTALLER.read_text()
        self.assertIn(f"        {version}:{target}) expected='{prepare.JAIL_SHA256}' ;;\n", script)


if __name__ == '__main__':
    unittest.main()
