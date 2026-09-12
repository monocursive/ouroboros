#!/usr/bin/env python3
import copy
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "scripts", "self-development-status.py")
STATUS = module_path = os.path.join(ROOT, "scripts", "self-development-status.py")
CAMPAIGN = os.path.join(ROOT, "scripts", "self-development-campaign.py")
FIXTURES = os.path.join(ROOT, "test", "fixtures", "self-development-status")
P2_FIXTURES = os.path.join(ROOT, "tmp", "roadmap-implementation-20260911", "p2-review-probes", "live")
AS_OF = "1789143700"


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


P2 = module(CAMPAIGN, "campaign_for_status_tests")
STATUS_MODULE = module(STATUS, "status_for_status_tests")


def run(*arguments):
    return subprocess.run([CLI, *arguments], text=True, capture_output=True, env={**os.environ, "PYTHONWARNINGS": "error"})


def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, allow_nan=False)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def bind_checkpoint(value):
    value["digest"] = digest(value["messages"])
    value["plan_digest"] = digest(value["plan"])
    return value


class StatusTest(unittest.TestCase):
    def checkpoints(self):
        return ["--checkpoint", os.path.join(FIXTURES, "checkpoint-old.json"), "--checkpoint", os.path.join(FIXTURES, "checkpoint-current.json"), "--as-of", AS_OF]

    def p2_args(self):
        return ["--receipt", os.path.join(P2_FIXTURES, "smoke-receipt.json"), "--manifest", os.path.join(P2_FIXTURES, "smoke-manifest.json"), "--key", os.path.join(P2_FIXTURES, "key")]

    def mutate_checkpoint(self, mutation, raw=None, filename="checkpoint.json", post_bind_mutation=lambda value: None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = os.path.join(os.path.realpath(temporary.name), filename)
        if raw is None:
            value = read_json(os.path.join(FIXTURES, "checkpoint-current.json"))
            mutation(value)
            bind_checkpoint(value)
            post_bind_mutation(value)
            write_json(path, value)
        else:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(raw)
        return path

    def signed_p2(self, receipt_mutation=lambda value: None, manifest_mutation=lambda value: None, post_sign_mutation=lambda value: None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = os.path.realpath(temporary.name)
        receipt = read_json(os.path.join(P2_FIXTURES, "smoke-receipt.json"))
        manifest = read_json(os.path.join(P2_FIXTURES, "smoke-manifest.json"))
        with open(os.path.join(P2_FIXTURES, "key"), "rb") as handle:
            key = handle.read()
        manifest_mutation(manifest)
        receipt["manifest_digest"] = P2.digest(manifest)
        receipt["source"] = manifest["source"]
        receipt["effective_conditions"] = P2.effective_conditions(manifest)
        if isinstance(manifest.get("receipt_policy"), dict):
            receipt["signer_id"] = manifest["receipt_policy"].get("signer_id")
            receipt["nonce"] = manifest["receipt_policy"].get("nonce")
        receipt_mutation(receipt)
        P2.sign_receipt(receipt, key)
        post_sign_mutation(receipt)
        receipt_path, manifest_path, key_path = [os.path.join(base, name) for name in ("receipt.json", "manifest.json", "key")]
        with open(receipt_path, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle)
        write_json(manifest_path, manifest)
        with open(key_path, "wb") as handle:
            handle.write(key)
        os.chmod(key_path, 0o600)
        return ["--receipt", receipt_path, "--manifest", manifest_path, "--key", key_path]

    def assert_refused(self, *arguments):
        process = run(*arguments)
        self.assertEqual(process.returncode, 2, process.stdout)
        self.assertFalse("Traceback" in process.stderr)

    def test_versioned_unknowns_and_neutral_checkpoint_selection(self):
        process = run(*self.checkpoints())
        self.assertEqual(process.returncode, 0, process.stderr)
        document = json.loads(process.stdout)
        self.assertEqual(document["schema_version"], 3)
        self.assertEqual(document["scope"], "regression_evidence_not_program_truth")
        self.assertEqual(document["checkpoint"]["completeness"], "unknown")
        self.assertEqual(document["checkpoint"]["input_count"], 2)
        self.assertNotIn("supersedes", document["checkpoint"])
        self.assertEqual(len(document["checkpoint"]["older_supplied_inputs"]), 1)
        self.assertEqual(document["validation"], {"status": "unknown", "reason": "not_supplied", "receipts": []})
        self.assertEqual(document["load"]["status"], "unknown")
        self.assertEqual(document["program_projection"]["status"], "unknown")
        self.assertEqual(document["items"][0]["phase"], "unknown")
        self.assertEqual(document["items"][1]["phase"], "pending")

    def test_digest_consistent_runtime_declarations_remain_explicitly_unestablished(self):
        declarations = (("accepted", "completed"), ("blocked", "unsettled"),
                        ("checking", "failed"), ("reviewing", "cancelled"),
                        ("investigating", "lost"))
        for work_state, settlement in declarations:
            with self.subTest(work_state=work_state, settlement=settlement):
                def mutation(value, work_state=work_state, settlement=settlement):
                    item = value["plan"]["plan"][0]
                    item.pop("owner_task_id", None)
                    item["work_state"] = work_state
                    item["status"] = {
                        "accepted": "completed", "blocked": "pending", "checking": "in_progress",
                        "reviewing": "in_progress", "investigating": "in_progress",
                    }[work_state]
                    item["child_settlement"] = settlement
                    if work_state == "accepted":
                        item.setdefault("acceptance", {
                            "actor": "parent", "decision_source": "parent_model",
                            "basis": "model_judgment", "evidence_validation": "unchecked_references",
                            "deterministic": False,
                        })
                    else:
                        item.pop("acceptance", None)
                    if work_state == "blocked":
                        item["blocker"] = {"type": "other", "resolvable_by_parent": True}
                    else:
                        item.pop("blocker", None)

                path = self.mutate_checkpoint(mutation)
                process = run("--checkpoint", path, "--as-of", AS_OF)
                self.assertEqual(process.returncode, 0, process.stderr)
                item = json.loads(process.stdout)["items"][0]
                self.assertEqual(item["work_state"], {
                    "declared": work_state, "establishment": "not_established", "observed": None,
                    "reason": "no authoritative runtime observation was supplied",
                })
                self.assertEqual(item["child_settlement"], {
                    "declared": settlement, "establishment": "not_established", "observed": None,
                    "reason": "no authoritative runtime observation was supplied",
                })
                rendered = run("--format", "markdown", "--checkpoint", path, "--as-of", AS_OF)
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                self.assertIn("declarations only", rendered.stdout)
                self.assertIn("**not established** for every row", rendered.stdout)
                self.assertIn("Declared state (not established)", rendered.stdout)
                self.assertIn("| %s | %s |" % (work_state, settlement), rendered.stdout)

    def test_complete_current_program_inventory_projects_blocked_without_false_completion(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        path = os.path.join(os.path.realpath(temporary.name), "program.json")
        items = []
        evidence = os.path.join(os.path.realpath(temporary.name), "evidence.json")
        write_json(evidence, {"evidence": "declaration only"})
        for item_id in STATUS_MODULE.PROGRAM_IDS:
            status = "blocked" if item_id in ("P0", "P1", "P4", "X1") else "pending"
            items.append({"id": item_id, "status": status, "reason": "current explicit disposition",
                          "evidence": [evidence]})
        write_json(path, {"schema_version": 1, "scope": "current_program",
                          "as_of": "2026-09-11T16:21:40Z", "complete_inventory": True,
                          "items": items, "unknowns": ["billing", "cache", "attention"]})
        process = run(*self.checkpoints(), "--program", path)
        self.assertEqual(process.returncode, 0, process.stderr)
        document = json.loads(process.stdout)
        self.assertEqual(document["scope"], "current_program_projection")
        self.assertEqual(document["program_projection"]["status"], "blocked")
        self.assertEqual([item["id"] for item in document["program_projection"]["items"]],
                         list(STATUS_MODULE.PROGRAM_IDS))
        self.assertEqual(document["program_projection"]["unknowns"], ["billing", "cache", "attention"])

        rendered = run(*self.checkpoints(), "--program", path, "--format", "markdown")
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertIn("## Current program inventory", rendered.stdout)
        self.assertTrue(rendered.stdout.startswith("# Current self-development program status\n"))
        self.assertIn("explicit conservative declaration", rendered.stdout)
        self.assertIn("Overall declaration: **blocked**", rendered.stdout)
        for item_id in STATUS_MODULE.PROGRAM_IDS:
            self.assertIn("| %s |" % item_id, rendered.stdout)
        for unknown in ("billing", "cache", "attention"):
            self.assertIn("- " + unknown, rendered.stdout)

    def test_current_program_inventory_refuses_missing_duplicate_and_false_pass_evidence(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        base = {"schema_version": 1, "scope": "current_program", "as_of": "2026-09-11T16:21:40Z",
                "complete_inventory": True, "unknowns": [],
                "items": [{"id": item_id, "status": "pending", "reason": "pending", "evidence": []}
                          for item_id in STATUS_MODULE.PROGRAM_IDS]}
        variants = [copy.deepcopy(base), copy.deepcopy(base), copy.deepcopy(base)]
        variants[0]["items"].pop()
        variants[1]["items"][-1]["id"] = "P0"
        variants[2]["items"][0].update(status="passed", evidence=[])
        for index, value in enumerate(variants):
            path = os.path.join(os.path.realpath(temporary.name), "program-%d.json" % index)
            write_json(path, value)
            self.assert_refused(*self.checkpoints(), "--program", path)

    def test_program_nonexistent_evidence_and_all_passed_declaration_refuse(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        base = os.path.realpath(temporary.name)
        missing = os.path.join(base, "does-not-exist.json")
        evidence = os.path.join(base, "evidence.json"); write_json(evidence, {"local": True})
        for name, evidence_path in (("missing", missing), ("all-passed", evidence)):
            value = {"schema_version": 1, "scope": "current_program", "as_of": "2026-09-11T16:21:40Z",
                     "complete_inventory": True, "unknowns": [],
                     "items": [{"id": item_id, "status": "passed" if name == "all-passed" else "pending",
                                "reason": "declaration", "evidence": [evidence_path]}
                               for item_id in STATUS_MODULE.PROGRAM_IDS]}
            path = os.path.join(base, name + ".json"); write_json(path, value)
            self.assert_refused(*self.checkpoints(), "--program", path)

    def test_failed_validation_dominates_unknown(self):
        failed = self.signed_p2(receipt_mutation=lambda value: value["constituents"][0].update(status="failed", exit_code=1))
        missing = self.signed_p2(receipt_mutation=lambda value: value.update(constituents=[]))
        process = run(*self.checkpoints(), *failed, *missing)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["validation"]["status"], "failed")

    def test_markdown_escapes_raw_html_evidence(self):
        path = self.mutate_checkpoint(lambda value: value["plan"]["plan"][1].update(evidence=["<img src=x onerror=alert(1)>"]))
        process = run("--format", "markdown", "--checkpoint", path, "--as-of", AS_OF)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn("<img", process.stdout)
        self.assertIn("&lt;img", process.stdout)

    def test_markdown_is_truthful_and_escapes_content_and_path(self):
        path = self.mutate_checkpoint(lambda value: value["plan"]["plan"][1].update(step="heading # x | `tick`"), filename="checkpoint-`odd|name`.json")
        process = run("--format", "markdown", "--checkpoint", path, "--as-of", AS_OF)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("regression evidence only, not actual program truth", process.stdout)
        self.assertIn("no supersession claim", run("--format", "markdown", *self.checkpoints()).stdout)
        self.assertIn("\\|", process.stdout)
        self.assertIn("\\`", process.stdout)
        self.assertIn("Load", process.stdout)

    def test_controls_are_refused_without_traceback(self):
        for hostile in ("row\n| injected", "carriage\rreturn", "ansi\x1b[31m", "bidi\u202etest"):
            with self.subTest(hostile=repr(hostile)):
                path = self.mutate_checkpoint(lambda value, hostile=hostile: value["plan"]["plan"][0].update(step=hostile))
                self.assert_refused("--checkpoint", path, "--as-of", AS_OF)

    def test_markdown_refuses_controls_from_paths_and_p2_reasons(self):
        path = self.mutate_checkpoint(lambda value: None, filename="good\n# INJECTED.json")
        process = run("--format", "markdown", "--checkpoint", path, "--as-of", AS_OF)
        self.assertEqual(process.returncode, 2, process.stdout)
        self.assertNotIn("# INJECTED", process.stdout + process.stderr)

        def hostile_manifest(value):
            value["execution"]["commands"][0]["id"] = "command\n# INJECTED"
        def hostile_receipt(value):
            value["constituents"][0]["command_id"] = "command\n# INJECTED"
            value["constituents"][0]["coverage_units"] = []
        arguments = self.signed_p2(receipt_mutation=hostile_receipt, manifest_mutation=hostile_manifest)
        process = run("--format", "markdown", *self.checkpoints(), *arguments)
        self.assertEqual(process.returncode, 2, process.stdout)
        self.assertNotIn("# INJECTED", process.stdout + process.stderr)

    def test_consumed_identity_survives_post_open_path_replacement(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        path = os.path.join(os.path.realpath(temporary.name), "checkpoint.json")
        replacement = os.path.join(os.path.realpath(temporary.name), "replacement.json")
        original = read_json(os.path.join(FIXTURES, "checkpoint-current.json"))
        write_json(path, original)
        write_json(replacement, original)
        opened_identity = os.stat(path).st_dev, os.stat(path).st_ino
        real_open = STATUS_MODULE.P2._open_regular
        replaced = False
        def replacing_open(open_path, name, maximum, owner=True, single_link=True):
            nonlocal replaced
            fd, info = real_open(open_path, name, maximum, owner, single_link)
            if open_path == path and not replaced:
                os.replace(replacement, path)
                replaced = True
            return fd, info
        STATUS_MODULE.P2._open_regular = replacing_open
        self.addCleanup(setattr, STATUS_MODULE.P2, "_open_regular", real_open)
        _, consumed_identity = STATUS_MODULE.load_json(path)
        self.assertEqual(consumed_identity, opened_identity)
        self.assertNotEqual(consumed_identity, (os.stat(path).st_dev, os.stat(path).st_ino))

    def test_p0_schema_conflicts_and_bogus_acceptance_are_refused(self):
        mutations = [
            lambda value: value["plan"]["plan"][0].update(status="pending"),
            lambda value: value["plan"]["plan"][0]["acceptance"].update(actor=""),
            lambda value: value["plan"]["plan"][0]["acceptance"].update(decision_source="child"),
            lambda value: value["plan"]["plan"][0].update(evidence=[]),
            lambda value: value["plan"]["plan"][1].update(child_settlement="invented"),
            lambda value: value["plan"]["plan"][1].update(blocker="scalar"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assert_refused("--checkpoint", self.mutate_checkpoint(mutation), "--as-of", AS_OF)

    def test_checkpoint_time_digest_types_and_bounds(self):
        stale = self.mutate_checkpoint(lambda value: value.update(updated_at="2026-09-09T00:00:00Z"))
        future = self.mutate_checkpoint(lambda value: value.update(updated_at="2026-09-12T12:00:00Z"))
        bad_digest = self.mutate_checkpoint(lambda value: None, post_bind_mutation=lambda value: value.update(plan_digest="x" * 64))
        boolean = self.mutate_checkpoint(lambda value: value.update(offset=True))
        too_many = self.mutate_checkpoint(lambda value: value["plan"].update(plan=[copy.deepcopy(value["plan"]["plan"][1]) for _ in range(257)]))
        def make_nested(value):
            nested_value = []
            for _ in range(34):
                nested_value = [nested_value]
            value["messages"].append(nested_value)
        nested = self.mutate_checkpoint(make_nested)
        for path in (stale, future, bad_digest, too_many, nested):
            self.assert_refused("--checkpoint", path, "--as-of", AS_OF)
        # Unconsumed checkpoint integer fields remain recursively type-safe, including booleans.
        self.assertEqual(run("--checkpoint", boolean, "--as-of", AS_OF).returncode, 0)

    def test_file_objects_aliases_and_paths_are_refused(self):
        source = os.path.join(FIXTURES, "checkpoint-current.json")
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        hardlink = os.path.join(temporary.name, "hard.json"); os.link(source, hardlink)
        symlink = os.path.join(temporary.name, "sym.json"); os.symlink(source, symlink)
        directory = os.path.join(temporary.name, "directory"); os.mkdir(directory)
        fifo = os.path.join(temporary.name, "fifo"); os.mkfifo(fifo)
        oversized = os.path.join(temporary.name, "large.json")
        with open(oversized, "wb") as handle: handle.write(b" " * (1_048_577))
        for path in (hardlink, symlink, directory, fifo, oversized):
            self.assert_refused("--checkpoint", path, "--as-of", AS_OF)
        self.assert_refused("--checkpoint", os.path.relpath(source, ROOT), "--as-of", AS_OF)

    def test_duplicate_and_ambiguous_inputs_are_refused(self):
        current = os.path.join(FIXTURES, "checkpoint-current.json")
        self.assert_refused("--checkpoint", current, "--checkpoint", current, "--as-of", AS_OF)
        duplicate = self.mutate_checkpoint(lambda value: None)
        self.assert_refused("--checkpoint", current, "--checkpoint", duplicate, "--as-of", AS_OF)

    def test_malformed_duplicate_key_nonfinite_and_oversized_text_refuse(self):
        malformed = self.mutate_checkpoint(None, raw="{")
        duplicate = self.mutate_checkpoint(None, raw='{"version":3,"version":3}')
        nonfinite = self.mutate_checkpoint(None, raw='{"number":NaN}')
        large_text = self.mutate_checkpoint(lambda value: value["plan"]["plan"][0].update(step="é" * 101))
        missing = os.path.join(os.path.dirname(malformed), "missing.json")
        for path in (malformed, duplicate, nonfinite, large_text, missing):
            self.assert_refused("--checkpoint", path, "--as-of", AS_OF)

    def test_historical_p2_uses_authoritative_validator_and_adjudicator(self):
        process = run(*self.checkpoints(), *self.p2_args())
        self.assertEqual(process.returncode, 0, process.stderr)
        receipt = json.loads(process.stdout)["validation"]["receipts"][0]
        # The retained fixture predates the current execution-condition projection.
        # It is still validated/authenticated, but must not be upgraded to a pass.
        self.assertEqual(receipt["status"], "unknown")
        self.assertEqual(receipt["classification"], "inconclusive")
        self.assertIn("non-reusable", receipt["reason"])
        self.assertIn("not inferred", receipt["reason"])
        self.assertIn("local HMAC integrity only", receipt["trust"])
        self.assertIn("not prove independent", receipt["trust"])

    def test_resigned_p2_contract_attacks_are_refused_or_unknown(self):
        refused_attacks = [
            self.signed_p2(manifest_mutation=lambda value: value["receipt_policy"].update(mode="independent")),
            self.signed_p2(manifest_mutation=lambda value: value["receipt_policy"].update(max_age_seconds=True)),
            self.signed_p2(receipt_mutation=lambda value: value.update(constituents=[1])),
            self.signed_p2(receipt_mutation=lambda value: value["constituents"][0].update(status="invented")),
            self.signed_p2(post_sign_mutation=lambda value: value.update(telemetry={"tool_calls": float("inf")})),
            self.signed_p2(receipt_mutation=lambda value: value["constituents"].append(copy.deepcopy(value["constituents"][0]))),
        ]
        for arguments in refused_attacks:
            with self.subTest(arguments=arguments):
                self.assert_refused(*self.checkpoints(), *arguments)
        stale_source = self.signed_p2(receipt_mutation=lambda value: value.update(source={"revision": "other", "tree_digest": value["source"]["tree_digest"]}))
        process = run(*self.checkpoints(), *stale_source)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["validation"]["status"], "unknown")
        missing = self.signed_p2(receipt_mutation=lambda value: value.update(constituents=[]))
        process = run(*self.checkpoints(), *missing)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["validation"]["status"], "unknown")

    def test_hmac_tamper_stale_future_key_policy_and_alignment_refuse(self):
        tampered = self.signed_p2()
        receipt = read_json(tampered[1]); receipt["invocation_id"] = "tampered"; write_json(tampered[1], receipt)
        stale = self.signed_p2(receipt_mutation=lambda value: value.update(issued_at=1))
        future = self.signed_p2(receipt_mutation=lambda value: value.update(issued_at=int(AS_OF) + 6))
        for arguments in (tampered, stale, future):
            self.assert_refused(*self.checkpoints(), *arguments)
        relative_key = self.p2_args(); relative_key[-1] = os.path.relpath(relative_key[-1], ROOT)
        self.assert_refused(*self.checkpoints(), *relative_key)
        self.assert_refused(*self.checkpoints(), "--receipt", self.p2_args()[1])


if __name__ == "__main__":
    unittest.main()
