"""The Harbor-facing class, checked without importing Harbor.

`agent.py` cannot be imported here — `harbor` is not installed on the machine this suite
runs on, and installing it to run a unit test would be pretending the adapter had been
exercised when it has not. So it is parsed instead: the AST tells us the class implements
the four members Harbor's `BaseInstalledAgent` declares abstract, with the right
signatures, and that it does not quietly acquire habits the README says it does not have.

This is a real but limited check, and the README says so. It cannot tell you the adapter
works; it can tell you it has not drifted away from the interface it was written against.
"""

import ast
import unittest
from pathlib import Path

AGENT = Path(__file__).resolve().parent.parent / "ouroboros_agent" / "agent.py"


def load_class() -> ast.ClassDef:
    tree = ast.parse(AGENT.read_text(encoding="utf-8"), filename=str(AGENT))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "OuroborosAgent":
            return node
    raise AssertionError("OuroborosAgent is not defined in agent.py")


class Shape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = load_class()
        cls.methods = {
            item.name: item
            for item in cls.node.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        cls.source = AGENT.read_text(encoding="utf-8")

    def test_it_subclasses_the_installed_agent_base(self):
        bases = [ast.unparse(base) for base in self.node.bases]
        self.assertEqual(bases, ["BaseInstalledAgent"])

    def test_name_is_a_staticmethod(self):
        node = self.methods["name"]
        decorators = [ast.unparse(d) for d in node.decorator_list]
        self.assertIn("staticmethod", decorators)
        self.assertEqual([a.arg for a in node.args.args], [])

    def test_the_four_abstract_members_are_implemented(self):
        for required in ("name", "version", "install", "run"):
            self.assertIn(required, self.methods, f"{required} is not implemented")

    def test_install_and_run_are_async(self):
        # Harbor 2.x is async throughout; a sync `run` is silently never awaited.
        self.assertIsInstance(self.methods["install"], ast.AsyncFunctionDef)
        self.assertIsInstance(self.methods["run"], ast.AsyncFunctionDef)

    def test_run_takes_the_three_arguments_harbor_passes(self):
        args = [a.arg for a in self.methods["run"].args.args]
        self.assertEqual(args, ["self", "instruction", "environment", "context"])

    def test_install_takes_the_environment(self):
        args = [a.arg for a in self.methods["install"].args.args]
        self.assertEqual(args, ["self", "environment"])

    def test_run_returns_none(self):
        # Harbor's contract: results are recorded by mutating `context`, not returned.
        returns = self.methods["run"].returns
        self.assertIsNotNone(returns)
        self.assertEqual(ast.unparse(returns), "None")

    def test_it_does_not_claim_atif(self):
        assignments = {
            target.id: ast.unparse(item.value)
            for item in self.node.body
            if isinstance(item, ast.Assign)
            for target in item.targets
            if isinstance(target, ast.Name)
        }
        self.assertEqual(assignments.get("SUPPORTS_ATIF"), "False")

    def test_the_turn_is_run_without_the_raising_helper(self):
        # `exec_as_agent`/`exec_as_root` raise on a non-zero exit. A turn that ends
        # `failed` is a measurement the task's tests are there to score; raising would
        # turn it into an errored trial and lose the number.
        run_source = ast.unparse(self.methods["run"])
        self.assertIn("environment.exec(", run_source)
        self.assertNotIn("exec_as_agent", run_source)
        self.assertNotIn("exec_as_root", run_source)

    def test_install_does_raise(self):
        # The opposite rule: an agent that could not install has nothing to say.
        install_source = ast.unparse(self.methods["install"])
        self.assertIn("raise RuntimeError", install_source)

    def test_it_never_builds_in_the_container(self):
        for forbidden in ("mix release", "cargo build", "mix compile", "make dist"):
            self.assertNotIn(f'"{forbidden}"', self.source)

    def test_the_dist_comes_from_the_documented_variable(self):
        self.assertIn('DIST_ENV = "OURO_LINUX_DIST"', self.source)


if __name__ == "__main__":
    unittest.main()
