#!/usr/bin/env python3
"""Focused integration and adversarial tests for self-development-campaign.py."""
import copy
import importlib.util
import json
import math
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PROGRAM = os.path.join(HERE, "self-development-campaign.py")
GATE_PROGRAM = os.path.join(HERE, "self-development-campaign-gate.py")
FIXTURE = os.path.join(os.path.dirname(HERE), "test", "fixtures", "self-development-campaign", "events.json")
SPEC = importlib.util.spec_from_file_location("campaign", PROGRAM)
campaign = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(campaign)
GATE_SPEC = importlib.util.spec_from_file_location("campaign_gate", GATE_PROGRAM)
campaign_gate = importlib.util.module_from_spec(GATE_SPEC); GATE_SPEC.loader.exec_module(campaign_gate)
PYTHON = os.path.realpath(sys.executable)


def benchmark(nonce="benchmark-nonce-0001"):
    return {"corpus_digest": "sha256:" + "c" * 64, "scope": "natural review", "model": "model-v1", "runtime": "runtime-v1", "environment": "local", "posture": "ask-sensitive", "bounds": {"tool_calls": 50, "turns": 20, "deadline_ms": 500000}, "event_boundaries": {"start": "submitted", "terminal": "completed"}, "action_taxonomy": ["approve", "decline"], "inclusion": ["parent_requests", "child_requests", "actions", "status:passed", "status:failed", "status:refused"], "permissible_variant_differences": []}


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.temp_root = os.path.realpath(self.temp.name); self.workspace = os.path.join(self.temp_root, "work"); os.mkdir(self.workspace)
        subprocess.run(["git", "init", "-q", self.workspace], check=True); subprocess.run(["git", "-C", self.workspace, "config", "user.email", "test@example.invalid"], check=True); subprocess.run(["git", "-C", self.workspace, "config", "user.name", "Test"], check=True)
        with open(os.path.join(self.workspace, "source.txt"), "w") as handle: handle.write("source\n")
        subprocess.run(["git", "-C", self.workspace, "add", "source.txt"], check=True); subprocess.run(["git", "-C", self.workspace, "commit", "-qm", "fixture"], check=True)
        self.key_path = os.path.join(self.temp_root, "receipt.key")
        with open(self.key_path, "wb") as handle: handle.write(b"k" * 32)
        os.chmod(self.key_path, 0o600); self.key = campaign.load_key(self.key_path); self.contract = self.make_manifest()

    def tearDown(self): self.temp.cleanup()

    def _owned_process_cleanup(self, pid):
        try:
            pgid = os.getpgid(pid)
        except ProcessLookupError:
            return
        def cleanup():
            try:
                if os.getpgid(pid) == pgid:
                    os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.addCleanup(cleanup)

    def _assert_heartbeat_stopped(self, path):
        before = os.path.getsize(path)
        time.sleep(.25)
        self.assertEqual(before, os.path.getsize(path))

    def make_manifest(self, mode="validation", commands=None, deadline=5000, nonce="local-nonce"):
        if commands is None: commands = [{"id": "one", "argv": [PYTHON, "-c", "open('one.json','w').write('ok')"], "cwd": self.workspace, "coverage_units": ["a"], "artifact_path": os.path.join(self.workspace, "one.json")}]
        value = {"schema_version": 2, "mode": mode, "workspace": self.workspace, "source": {"revision": "pending", "tree_digest": "sha256:" + "0" * 64}, "receipt_policy": {"mode": "local_integrity", "signer_id": "local-controller", "nonce": nonce, "max_age_seconds": 3600}, "execution": {"environment": {}, "environment_policy": "trusted_controller_allowlist_v1", "start_mode": "existing", "outer_sandbox": "forbidden", "containment": {"required": "cooperative_pgid"}, "requested_deadline_ms": deadline, "effective_deadline_ms": deadline, "allowed_executables": [{"path": PYTHON, "sha256": campaign.file_digest(PYTHON), "env_allowlist": []}], "commands": commands}, "coverage": {"required_units": [u for c in commands for u in c["coverage_units"]] + ["host"], "exclusions": [{"unit": "host", "reason": "host-only gate unavailable"}]}}
        if mode == "benchmark": value["benchmark"] = benchmark(nonce)
        value["source"] = campaign.measure_source(value); return value

    def rejects(self, value, phrase):
        with self.assertRaises(campaign.ContractError) as caught: campaign.validate_manifest(value)
        self.assertIn(phrase, str(caught.exception))

    def execute(self, contract=None, events=None): return campaign.execute_manifest(contract or self.contract, self.key, events=events)

    def test_execute_pass_binds_artifact_source_conditions_and_fd_identity(self):
        receipt = self.execute(); result = campaign.adjudicate(self.contract, receipt, self.key)
        self.assertEqual("passed", result["classification"]); self.assertTrue(result["reusable"])
        item = receipt["constituents"][0]; self.assertEqual(0, item["exit_code"]); self.assertEqual(campaign.file_digest(item["artifact"]["path"]), item["artifact"]["sha256"])
        self.assertIn("workload_digest", receipt["effective_conditions"]); self.assertEqual("cooperative_pgid", receipt["effective_conditions"]["containment"]["effective"])

    def test_controller_supplies_exact_declared_artifact_path(self):
        artifact = os.path.join(self.workspace, "declared.json")
        code = "import os; open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('gate')"
        command = {"id":"artifact-env","argv":[PYTHON,"-c",code],"cwd":self.workspace,
                   "coverage_units":["artifact-env"],"artifact_path":artifact}
        contract = self.make_manifest(commands=[command])
        receipt = self.execute(contract)
        self.assertEqual("passed", receipt["constituents"][0]["status"])
        with open(artifact, encoding="utf-8") as handle:
            self.assertEqual("gate", handle.read())

    def test_gate_validation_child_gets_exact_authenticated_environment(self):
        artifact = os.path.join(self.workspace, "environment.json")
        declared = {"CI":"declared","PATH":"/usr/bin:/bin","SOURCE_DATE_EPOCH":"123","TZ":"UTC"}
        code = "import json,os,sys; open(sys.argv[1],'w').write(json.dumps(dict(os.environ),sort_keys=True))"
        exit_code = campaign_gate.run_bounded([PYTHON,"-c",code,artifact], self.workspace,
                                                declared, os.path.join(self.workspace,"gate.txt"), limit=4096)
        self.assertEqual(0, exit_code)
        with open(artifact, encoding="utf-8") as handle:
            observed = json.load(handle)
        # macOS may add these two process-bootstrap values; no declared value may
        # be dropped/replaced/defaulted by the gate itself.
        for key in ("LC_CTYPE", "__CF_USER_TEXT_ENCODING"):
            observed.pop(key, None)
        self.assertEqual(declared, observed)

    def test_retired_machine_specific_gate_shortcuts_refuse_without_spawning(self):
        artifact = os.path.join(self.workspace, "retired-gate.txt")
        controls = {campaign_gate.ARTIFACT_ENV: artifact,
                    campaign_gate.DECLARED_ENV: "{}"}
        for name in ("elixir", "elixir-owner-lifecycle", "python-campaign",
                     "python-maintenance", "python-status", "rust-cli", "rust-fmt"):
            with self.subTest(name=name), mock.patch.dict(os.environ, controls, clear=True), \
                    mock.patch.object(campaign_gate, "run_bounded") as run, \
                    mock.patch("sys.stderr"):
                self.assertEqual(2, campaign_gate.main([GATE_PROGRAM, name]))
                run.assert_not_called()
                self.assertFalse(os.path.exists(artifact))

    def test_retired_gate_cli_explains_direct_manifest_replacement(self):
        result = subprocess.run([PYTHON, GATE_PROGRAM, "python-maintenance"],
                                env={}, capture_output=True, text=True, timeout=3)
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertIn("artifact_mode: stdout", result.stderr)
        self.assertIn("absolute executable", result.stderr)

    def test_gate_streams_bounded_output_and_makes_overflow_nonpassing_explicit(self):
        artifact = os.path.join(self.workspace, "bounded.txt")
        exit_code = campaign_gate.run_bounded(
            [PYTHON,"-c","import sys; sys.stdout.write('x'*20000)"], self.workspace,
            {}, artifact, limit=1024)
        self.assertEqual(campaign_gate.OVERFLOW_EXIT, exit_code)
        self.assertLessEqual(os.path.getsize(artifact), 1024)
        with open(artifact, "rb") as handle:
            self.assertTrue(handle.read().endswith(campaign_gate.OVERFLOW_MARKER))

    def test_gate_local_timeout_stops_ordinary_descendant(self):
        heartbeat = os.path.join(self.workspace, "gate-heartbeat")
        pidfile = os.path.join(self.workspace, "gate-child.pid")
        child = "import os,time;open(%r,'w').write(str(os.getpid()))\nwhile True:\n open(%r,'a').write('x');time.sleep(.03)" % (pidfile, heartbeat)
        parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);time.sleep(30)" % child
        artifact = os.path.join(self.workspace, "gate-timeout.txt")
        self.assertEqual(124, campaign_gate.run_bounded([PYTHON, "-c", parent], self.workspace, {}, artifact, limit=1024, timeout=.2))
        with open(pidfile, encoding="ascii") as handle:
            child_pid = int(handle.read())
        self._owned_process_cleanup(child_pid)
        self._assert_heartbeat_stopped(heartbeat)

    def test_external_gate_cancellation_stops_ordinary_descendant(self):
        heartbeat = os.path.join(self.workspace, "cancel-heartbeat")
        pidfile = os.path.join(self.workspace, "cancel-child.pid")
        child = "import os,time;open(%r,'w').write(str(os.getpid()))\nwhile True:\n open(%r,'a').write('x');time.sleep(.03)" % (pidfile, heartbeat)
        command = [PYTHON, "-c", "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);time.sleep(30)" % child]
        driver = "import importlib.util,sys;spec=importlib.util.spec_from_file_location('g',sys.argv[1]);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g);raise SystemExit(g.run_bounded(%r,sys.argv[2],{},sys.argv[3],limit=1024,timeout=30))" % command
        gate = subprocess.Popen([PYTHON, "-c", driver, GATE_PROGRAM, self.workspace, os.path.join(self.workspace, "cancel.txt")], start_new_session=True)
        gate_pgid = gate.pid
        def cleanup_gate():
            try:
                if os.getpgid(gate.pid) == gate_pgid:
                    os.killpg(gate_pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.addCleanup(cleanup_gate)
        deadline = time.monotonic() + 2
        while not os.path.exists(pidfile) and time.monotonic() < deadline: time.sleep(.02)
        with open(pidfile, encoding="ascii") as handle:
            child_pid = int(handle.read())
        self._owned_process_cleanup(child_pid)
        gate.send_signal(signal.SIGTERM)
        self.assertEqual(128 + signal.SIGTERM, gate.wait(timeout=3))
        self._assert_heartbeat_stopped(heartbeat)

    def test_abrupt_outer_gate_sigkill_stops_ordinary_descendant(self):
        heartbeat = os.path.join(self.workspace, "kill-heartbeat")
        pidfile = os.path.join(self.workspace, "kill-child.pid")
        child = "import os,time;open(%r,'w').write(str(os.getpid()))\nwhile True:\n open(%r,'a').write('x');time.sleep(.03)" % (pidfile, heartbeat)
        command = [PYTHON, "-c", "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);time.sleep(30)" % child]
        driver = "import importlib.util,sys;spec=importlib.util.spec_from_file_location('g',sys.argv[1]);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g);raise SystemExit(g.run_bounded(%r,sys.argv[2],{},sys.argv[3],limit=1024,timeout=30))" % command
        gate = subprocess.Popen([PYTHON, "-c", driver, GATE_PROGRAM, self.workspace, os.path.join(self.workspace, "kill.txt")], start_new_session=True)
        gate_pgid = gate.pid
        def cleanup_gate():
            try:
                if os.getpgid(gate.pid) == gate_pgid:
                    os.killpg(gate_pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.addCleanup(cleanup_gate)
        deadline = time.monotonic() + 2
        while not os.path.exists(pidfile) and time.monotonic() < deadline: time.sleep(.02)
        with open(pidfile, encoding="ascii") as handle:
            child_pid = int(handle.read())
        validation_pgid = os.getpgid(child_pid)
        self._owned_process_cleanup(child_pid)
        self.assertNotEqual(gate_pgid, validation_pgid)
        os.killpg(gate_pgid, signal.SIGKILL)
        self.assertEqual(-signal.SIGKILL, gate.wait(timeout=3))
        self._assert_heartbeat_stopped(heartbeat)

    def test_outer_timeout_escalation_stops_nested_ordinary_descendant(self):
        heartbeat = os.path.join(self.workspace, "escalation-heartbeat")
        pidfile = os.path.join(self.workspace, "escalation-child.pid")
        child = "import os,time;open(%r,'w').write(str(os.getpid()))\nwhile True:\n open(%r,'a').write('x');time.sleep(.03)" % (pidfile, heartbeat)
        command = [PYTHON, "-c", "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',%r]);time.sleep(30)" % child]
        driver = "import importlib.util,sys;spec=importlib.util.spec_from_file_location('g',sys.argv[1]);g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g);raise SystemExit(g.run_bounded(%r,sys.argv[2],{},sys.argv[3],limit=1024,timeout=30))" % command
        gate = subprocess.Popen([PYTHON, "-c", driver, GATE_PROGRAM, self.workspace, os.path.join(self.workspace, "escalation.txt")], start_new_session=True)
        gate_pgid = gate.pid
        def cleanup_gate():
            try:
                if os.getpgid(gate.pid) == gate_pgid:
                    os.killpg(gate_pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.addCleanup(cleanup_gate)
        deadline = time.monotonic() + 2
        while not os.path.exists(pidfile) and time.monotonic() < deadline: time.sleep(.02)
        with open(pidfile, encoding="ascii") as handle:
            child_pid = int(handle.read())
        self._owned_process_cleanup(child_pid)
        os.kill(gate.pid, signal.SIGSTOP)
        campaign._terminate_group(gate, .05)
        self.assertEqual(-signal.SIGKILL, gate.wait(timeout=3))
        self._assert_heartbeat_stopped(heartbeat)
        try:
            self.assertNotEqual(gate_pgid, os.getpgid(child_pid))
        except ProcessLookupError:
            pass

    def test_gate_closes_pipe_on_success_nonzero_timeout_and_error(self):
        real_popen = subprocess.Popen
        streams = []
        def capture(*args, **kwargs):
            process = real_popen(*args, **kwargs); streams.append(process.stdout); return process
        cases = [([PYTHON, "-c", "pass"], 0, 2),
                 ([PYTHON, "-c", "raise SystemExit(7)"], 7, 2),
                 ([PYTHON, "-c", "import time;time.sleep(30)"], 124, .05)]
        with mock.patch.object(campaign_gate.subprocess, "Popen", side_effect=capture):
            for index, (argv, expected, timeout) in enumerate(cases):
                self.assertEqual(expected, campaign_gate.run_bounded(argv, self.workspace, {}, os.path.join(self.workspace, "close-%d" % index), limit=1024, timeout=timeout))
                self.assertTrue(streams[-1].closed)
            existing = os.path.join(self.workspace, "existing")
            with open(existing, "wb"):
                pass
            with self.assertRaises(FileExistsError):
                campaign_gate.run_bounded([PYTHON, "-c", "import time;time.sleep(30)"], self.workspace, {}, existing, limit=1024, timeout=2)
            self.assertTrue(streams[-1].closed)
        with self.assertRaises(FileNotFoundError):
            campaign_gate.run_bounded([os.path.join(self.workspace, "missing")], self.workspace, {}, os.path.join(self.workspace, "spawn-error"), limit=1024)

    def test_failure_missing_artifact_and_deadline_never_pass(self):
        command = {"id":"bad","argv":[PYTHON,"-c","raise SystemExit(7)"],"cwd":self.workspace,"coverage_units":["bad"],"artifact_path":os.path.join(self.workspace,"bad.json")}
        contract = self.make_manifest(commands=[command]); receipt = self.execute(contract); self.assertEqual("failed", campaign.adjudicate(contract, receipt, self.key)["classification"])
        command["argv"] = [PYTHON,"-c","pass"]; contract = self.make_manifest(commands=[command]); self.assertEqual("inconclusive", self.execute(contract)["constituents"][0]["status"])
        value = copy.deepcopy(self.contract); value["execution"]["commands"][0]["deadline_ms"] = 600001; self.rejects(value, "600000")

    def test_cooperative_timeout_kills_same_group(self):
        heartbeat = os.path.join(self.workspace,"heartbeat"); child = "import time; p=%r\nwhile True:\n open(p,'a').write('x'); time.sleep(.05)" % heartbeat; parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); time.sleep(30)" % child
        contract = self.make_manifest(commands=[{"id":"slow","argv":[PYTHON,"-c",parent],"cwd":self.workspace,"coverage_units":["slow"],"artifact_path":heartbeat}], deadline=250); receipt = self.execute(contract)
        self.assertEqual("timeout", receipt["constituents"][0]["status"]); size=os.path.getsize(heartbeat); time.sleep(.3); self.assertEqual(size,os.path.getsize(heartbeat))

    def test_detached_escape_requires_strong_containment_and_refuses_before_execution(self):
        marker=os.path.join(self.workspace,"must-not-exist"); code="import subprocess,sys; subprocess.Popen([sys.executable,'-c',%r],start_new_session=True)" % ("open(%r,'w').write('escaped')" % marker)
        contract=self.make_manifest(commands=[{"id":"escape","argv":[PYTHON,"-c",code],"cwd":self.workspace,"coverage_units":["escape"],"artifact_path":marker}]); contract["execution"]["containment"]["required"]="strong_descendants"; contract["source"]=campaign.measure_source(contract)
        with self.assertRaisesRegex(campaign.ContractError,"refusing before execution"): self.execute(contract)
        self.assertFalse(os.path.exists(marker))

    def test_direct_argv_paths_coverage_and_sandbox_contract(self):
        value=copy.deepcopy(self.contract); value["execution"]["commands"][0]["argv"]="echo unsafe"; self.rejects(value,"command.argv")
        value=copy.deepcopy(self.contract); value["execution"]["commands"][0]["argv"][0]="python3"; self.rejects(value,"absolute canonical")
        value=copy.deepcopy(self.contract); value["execution"]["commands"][0]["cwd"]=self.temp_root; self.rejects(value,"escapes workspace")
        value=copy.deepcopy(self.contract); value["coverage"]["required_units"].append("missing"); self.rejects(value,"incomplete coverage")
        value=copy.deepcopy(self.contract); value["execution"]["outer_sandbox"]="required"
        with self.assertRaisesRegex(campaign.ContractError,"unavailable"): self.execute(value)

    def test_environment_is_explicit_per_executable_allowlist(self):
        for key in ("SSH_AUTH_SOCK","AWS_CONFIG_FILE","SSL_CERT_FILE","REQUESTS_CA_BUNDLE","GIT_CONFIG_GLOBAL","PLUGIN_PATH","HOME","PYTHONPATH"):
            value=copy.deepcopy(self.contract); value["execution"]["environment"]={key:"evil"}
            with self.subTest(key=key): self.rejects(value,"safe controller allowlist")
        value=copy.deepcopy(self.contract); value["execution"]["environment"]={"LANG":"C"}; self.rejects(value,"not allowed for executable")
        value["execution"]["allowed_executables"][0]["env_allowlist"]=["LANG"]; campaign.validate_manifest(value)
        value=copy.deepcopy(self.contract); value["execution"]["environment"]={"PATH":"/usr/bin:/bin"}; self.rejects(value,"not allowed for executable")
        value["execution"]["allowed_executables"][0]["env_allowlist"]=["PATH"]; campaign.validate_manifest(value)

    def test_inventory_style_file_partitions_cwds_executables_and_environment_overlays(self):
        subdir = os.path.join(self.workspace, "tui"); os.mkdir(subdir)
        files = ["test/%03d_test.exs" % index for index in range(240)]
        chunks = [files[index:index + 40] for index in range(0, len(files), 40)]
        self.assertEqual(files, [path for chunk in chunks for path in chunk])
        self.assertEqual(240, len(set().union(*(set(chunk) for chunk in chunks))))
        commands = []
        for index, chunk in enumerate(chunks):
            commands.append({"id":"elixir-%d" % index,"argv":[PYTHON,"-c","pass"] + chunk,
                             "cwd":self.workspace,"coverage_units":["elixir:" + path for path in chunk],
                             "artifact_path":os.path.join(self.workspace,"elixir-%d.json" % index),
                             "environment":{"MIX_ENV":"test","PATH":"/usr/bin:/bin"},"deadline_ms":600000})
        commands.extend([
            {"id":"wasm-prerequisite","argv":[PYTHON,"-c","open('helper','w').write('wasm')"],"cwd":subdir,
             "coverage_units":["wasm-helper-build"],"artifact_path":os.path.join(subdir,"helper"),"environment":{"PATH":"/usr/bin:/bin"},"deadline_ms":600000},
            {"id":"rust-test","argv":[PYTHON,"-c","pass"],"cwd":subdir,"coverage_units":["rust-root-test"],
             "artifact_path":os.path.join(subdir,"rust.json"),"environment":{"OUROBOROS_REQUIRE_WASM":"1","OUROBOROS_WASM_HELPER":os.path.join(subdir,"helper"),"PATH":"/usr/bin:/bin"},"deadline_ms":600000,"requires":["wasm-prerequisite"]},
            {"id":"shell-static","argv":[PYTHON,"-c","pass"],"cwd":self.workspace,"coverage_units":["script-static"],
             "artifact_path":os.path.join(self.workspace,"shell.json"),"environment":{"SHELL":PYTHON},"deadline_ms":600000}])
        manifest = self.make_manifest(commands=commands, deadline=len(commands) * 600000)
        allowed = manifest["execution"]["allowed_executables"][0]
        allowed["env_allowlist"] = ["MIX_ENV","OUROBOROS_REQUIRE_WASM","OUROBOROS_WASM_HELPER","PATH","SHELL"]
        campaign.validate_manifest(manifest)
        conditions = campaign.effective_conditions(manifest)
        self.assertEqual(commands[7]["environment"], conditions["command_environments"]["rust-test"])
        self.assertEqual(600000, conditions["command_deadlines_ms"]["elixir-0"])
        self.assertEqual(subdir, commands[7]["cwd"])

    def test_command_overlay_is_exact_in_child_and_authenticated_receipt(self):
        artifact = os.path.join(self.workspace, "overlay.json")
        code = "import json,os;open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write(json.dumps({'process':dict(os.environ),'declared':json.loads(os.environ['OUROBOROS_CAMPAIGN_DECLARED_ENV'])},sort_keys=True))"
        command = {"id":"overlay","argv":[PYTHON,"-c",code],"cwd":self.workspace,"coverage_units":["overlay"],"artifact_path":artifact,"environment":{"MIX_ENV":"test","PATH":"/usr/bin:/bin"},"deadline_ms":600000}
        manifest = self.make_manifest(commands=[command]); manifest["execution"]["environment"]={"CI":"declared"}; manifest["execution"]["allowed_executables"][0]["env_allowlist"]=["CI","MIX_ENV","PATH"]
        receipt = self.execute(manifest)
        with open(artifact, encoding="utf-8") as handle: observed=json.load(handle)
        expected={"CI":"declared","MIX_ENV":"test","PATH":"/usr/bin:/bin"}; process=observed["process"]
        for key in ("LC_CTYPE","__CF_USER_TEXT_ENCODING"): process.pop(key,None)
        process.pop(campaign.ARTIFACT_ENV); process.pop(campaign.DECLARED_ENV)
        self.assertEqual(expected, process); self.assertEqual(expected, observed["declared"])
        self.assertEqual(command["environment"], receipt["effective_conditions"]["command_environments"]["overlay"])
        self.assertEqual("passed", receipt["constituents"][0]["status"]); self.assertIsNotNone(receipt["constituents"][0]["artifact"])

    def test_command_environment_deadline_and_prerequisite_contract_fail_closed(self):
        command = self.contract["execution"]["commands"][0]
        command["environment"] = {"MIX_ENV":"test"}; command["deadline_ms"] = 600000
        self.contract["execution"]["allowed_executables"][0]["env_allowlist"] = ["MIX_ENV"]
        campaign.validate_manifest(self.contract)
        bad = copy.deepcopy(self.contract); bad["execution"]["commands"][0]["environment"] = {"PYTHONHOME":"hidden"}; self.rejects(bad, "safe controller allowlist")
        bad = copy.deepcopy(self.contract); bad["execution"]["commands"][0]["deadline_ms"] = 600001; self.rejects(bad, "600000")
        bad = copy.deepcopy(self.contract); bad["execution"]["commands"][0]["requires"] = ["later"]; self.rejects(bad, "earlier commands")
        prerequisite = copy.deepcopy(command); prerequisite.update(id="pre", argv=[PYTHON,"-c","raise SystemExit(7)"], coverage_units=["pre"], artifact_path=os.path.join(self.workspace,"pre")); prerequisite.pop("requires",None)
        dependent = copy.deepcopy(command); dependent.update(id="dependent", coverage_units=["dependent"], artifact_path=os.path.join(self.workspace,"dependent"), requires=["pre"])
        manifest = self.make_manifest(commands=[prerequisite, dependent]); manifest["execution"]["allowed_executables"][0]["env_allowlist"]=["MIX_ENV"]
        receipt = self.execute(manifest)
        self.assertEqual(["failed", "skipped"], [item["status"] for item in receipt["constituents"]])
        self.assertIsNone(receipt["constituents"][1]["artifact"])

    def test_runner_output_overflow_is_explicit_nonpassing(self):
        artifact = os.path.join(self.workspace, "overflow.json")
        command = {"id":"overflow","argv":[PYTHON,"-c","import os;open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('ok');print('x'*%d)" % campaign.MAX_OUTPUT_BYTES],"cwd":self.workspace,"coverage_units":["overflow"],"artifact_path":artifact,"deadline_ms":5000}
        manifest = self.make_manifest(commands=[command]); receipt = self.execute(manifest); item=receipt["constituents"][0]
        self.assertEqual("failed", item["status"]); self.assertTrue(item["output_truncated"]); self.assertEqual(0,item["exit_code"])
        self.assertEqual("failed", campaign.adjudicate(manifest,receipt,self.key)["classification"])

    def test_runner_output_limit_does_not_cap_unrelated_command_files(self):
        side_effect = os.path.join(self.workspace, ".git", "large-side-effect")
        artifact = os.path.join(self.workspace, "bounded-output.json")
        command = {"id":"bounded","argv":[PYTHON,"-c","import os;open(%r,'wb').write(b'x'*(%d+1));print('ok')" % (side_effect, campaign.MAX_OUTPUT_BYTES)],"cwd":self.workspace,"coverage_units":["bounded"],"artifact_path":artifact,"artifact_mode":"stdout","deadline_ms":5000}
        manifest = self.make_manifest(commands=[command]); receipt = self.execute(manifest); item=receipt["constituents"][0]
        self.assertEqual("passed", item["status"]); self.assertEqual(0,item["exit_code"])
        self.assertEqual(campaign.MAX_OUTPUT_BYTES + 1, os.path.getsize(side_effect))
        limits = item = receipt["effective_conditions"]["resource_limits"]
        self.assertEqual(campaign.MAX_PROCESS_FILE_BYTES, limits["process_file_bytes"])
        self.assertEqual(campaign.MAX_OUTPUT_BYTES, limits["captured_output_bytes"])
        self.assertEqual(campaign.MAX_ARTIFACT_BYTES, limits["receipt_artifact_bytes"])

    def test_process_file_ceiling_accommodates_observed_rust_output_class(self):
        side_effect = os.path.join(self.workspace, ".git", "rust-sized-output")
        observed_required = 149_859_880
        artifact = os.path.join(self.workspace, "rust-sized-output.log")
        code = "import os; f=open(%r,'wb'); f.truncate(%d); f.close(); print('ok')" % (side_effect, observed_required)
        command = {"id":"rust-sized","argv":[PYTHON,"-c",code],"cwd":self.workspace,"coverage_units":["rust-sized"],"artifact_path":artifact,"artifact_mode":"stdout","deadline_ms":5000}
        manifest = self.make_manifest(commands=[command]); receipt = self.execute(manifest); item=receipt["constituents"][0]
        self.assertEqual("passed", item["status"]); self.assertEqual(observed_required, os.path.getsize(side_effect))
        self.assertLess(observed_required, campaign.MAX_PROCESS_FILE_BYTES)

    def test_omitted_command_deadline_reports_actual_cap_and_old_conditions_refuse_reuse(self):
        manifest = self.make_manifest(deadline=1200000)
        self.assertEqual(600000, campaign.effective_conditions(manifest)["command_deadlines_ms"]["one"])
        receipt = self.execute(manifest); old = copy.deepcopy(receipt); old["effective_conditions"].pop("conditions_version"); old["effective_conditions"].pop("command_environments"); old["effective_conditions"].pop("command_deadlines_ms"); campaign.sign_receipt(old,self.key)
        result = campaign.adjudicate(manifest,old,self.key)
        self.assertEqual("inconclusive",result["classification"]); self.assertIn("intentionally non-reusable",result["reasons"][0])

    def test_legacy_conditions_partial_cannot_authorize_dependent_continuation(self):
        trace=os.path.join(self.workspace,".git","continuation-trace")
        def command(name,requires=None): return {"id":name,"argv":[PYTHON,"-c","import os;open(%r,'a').write(%r);open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('ok')"%(trace,name)],"cwd":self.workspace,"coverage_units":[name],"artifact_path":os.path.join(self.workspace,name+".log"),"requires":requires or []}
        manifest=self.make_manifest(commands=[command("first"),command("second",["first"])]); partial=campaign.execute_manifest(manifest,self.key,command_id="first")
        old=copy.deepcopy(partial); old["effective_conditions"].pop("conditions_version"); campaign.sign_receipt(old,self.key)
        with self.assertRaisesRegex(campaign.ContractError,"structurally eligible"): campaign.execute_manifest(manifest,self.key,reuse=old,command_id="second")
        with open(trace,encoding="utf-8") as handle: self.assertEqual("first",handle.read())

    def test_failed_or_unauthenticated_partial_cannot_satisfy_prerequisite(self):
        first={"id":"first","argv":[PYTHON,"-c","import os;open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('a')"],"cwd":self.workspace,"coverage_units":["a"],"artifact_path":os.path.join(self.workspace,"a")}
        second={"id":"second","argv":[PYTHON,"-c","import os;open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('b')"],"cwd":self.workspace,"coverage_units":["b"],"artifact_path":os.path.join(self.workspace,"b"),"requires":["first"]}
        manifest=self.make_manifest(commands=[first,second]); partial=campaign.execute_manifest(manifest,self.key,command_id="first")
        failed=copy.deepcopy(partial); failed["constituents"][0]["status"]="failed"; campaign.sign_receipt(failed,self.key)
        forged=copy.deepcopy(partial); forged["authentication"]["signature"]="0"*64
        for prior in (failed,forged):
            with self.assertRaisesRegex(campaign.ContractError,"structurally eligible"): campaign.execute_manifest(manifest,self.key,reuse=prior,command_id="second")

    def test_self_dependency_is_rejected_during_validation(self):
        self.contract["execution"]["commands"][0]["requires"]=["one"]
        self.rejects(self.contract,"earlier commands")

    def test_stdout_artifact_mode_captures_direct_output_and_preserves_exit(self):
        artifact=os.path.join(self.workspace,"stdout.log"); command={"id":"direct","argv":[PYTHON,"-c","import sys;print('out');print('err',file=sys.stderr)"],"cwd":self.workspace,"coverage_units":["direct"],"artifact_path":artifact,"artifact_mode":"stdout","deadline_ms":2000}
        manifest=self.make_manifest(commands=[command]); receipt=self.execute(manifest); item=receipt["constituents"][0]
        self.assertEqual(("passed",0),(item["status"],item["exit_code"])); self.assertIsNotNone(item["artifact"])
        with open(artifact,encoding="utf-8") as handle: self.assertEqual({"out","err"},set(handle.read().splitlines()))
        command["argv"]=[PYTHON,"-c","print('evidence');raise SystemExit(7)"]; manifest=self.make_manifest(commands=[command]); item=self.execute(manifest)["constituents"][0]
        self.assertEqual(("failed",7),(item["status"],item["exit_code"])); self.assertIsNotNone(item["artifact"])
        with open(artifact,encoding="utf-8") as handle: self.assertEqual("evidence\n",handle.read())

    def test_mix_build_path_is_command_only_and_workspace_contained(self):
        build=os.path.join(self.workspace,".campaign-build"); command=self.contract["execution"]["commands"][0]; command["environment"]={"MIX_BUILD_PATH":build}; self.contract["execution"]["allowed_executables"][0]["env_allowlist"]=["MIX_BUILD_PATH"]
        campaign.validate_manifest(self.contract)
        bad=copy.deepcopy(self.contract); bad["execution"]["commands"][0]["environment"]["MIX_BUILD_PATH"]=self.temp_root; self.rejects(bad,"escapes workspace")
        bad=copy.deepcopy(self.contract); bad["execution"]["environment"]={"MIX_BUILD_PATH":build}; self.rejects(bad,"safe controller allowlist")

    def test_owned_campaign_path_keys_are_command_only_workspace_contained(self):
        keys={"BOOT_GATE_OUT","CARGO_HOME","CARGO_TARGET_DIR","J2_BOOT_GATE_OUT","J3_BOOT_GATE_OUT","MIX_HOME","OUROBOROS_PROCESS_ID_HELPER","OUROBOROS_SDK_TEST_ROOT","OUROBOROS_WASM_EXAMPLES_ROOT","OUROBOROS_WASM_GUEST","OUROBOROS_WASM_HELPER","OUROBOROS_WASM_SKEW_DIR"}
        command=self.contract["execution"]["commands"][0]; command["environment"]={key:os.path.join(self.workspace,key.lower()) for key in keys}; self.contract["execution"]["allowed_executables"][0]["env_allowlist"]=sorted(keys)
        campaign.validate_manifest(self.contract)
        for key in keys:
            bad=copy.deepcopy(self.contract); bad["execution"]["commands"][0]["environment"][key]=self.temp_root; self.rejects(bad,"escapes workspace")
        bad=copy.deepcopy(self.contract); bad["execution"]["environment"]={"CARGO_TARGET_DIR":os.path.join(self.workspace,"target")}; self.rejects(bad,"safe controller allowlist")

    def test_rustup_home_is_an_explicit_existing_toolchain_directory(self):
        rustup=os.path.join(self.temp_root,"rustup"); os.mkdir(rustup)
        command=self.contract["execution"]["commands"][0]; command["environment"]={"RUSTUP_HOME":rustup}; self.contract["execution"]["allowed_executables"][0]["env_allowlist"]=["RUSTUP_HOME"]
        campaign.validate_manifest(self.contract)
        missing=copy.deepcopy(self.contract); missing["execution"]["commands"][0]["environment"]["RUSTUP_HOME"]=os.path.join(self.temp_root,"missing"); self.rejects(missing,"does not exist")
        relative=copy.deepcopy(self.contract); relative["execution"]["commands"][0]["environment"]["RUSTUP_HOME"]="rustup"; self.rejects(relative,"must be an absolute")
        link=os.path.join(self.temp_root,"rustup-link"); os.symlink(rustup,link); linked=copy.deepcopy(self.contract); linked["execution"]["commands"][0]["environment"]["RUSTUP_HOME"]=link; self.rejects(linked,"absolute canonical path")

    def test_home_is_command_only_workspace_contained_and_not_inherited(self):
        home=os.path.join(self.workspace,"campaign-home"); command=self.contract["execution"]["commands"][0]; command["environment"]={"HOME":home}; self.contract["execution"]["allowed_executables"][0]["env_allowlist"]=["HOME"]
        campaign.validate_manifest(self.contract)
        missing=copy.deepcopy(self.contract); missing["execution"]["commands"][0]["environment"]={}; missing["execution"]["commands"][0]["argv"]=[PYTHON,"-c","import os;raise SystemExit(1 if 'HOME' in os.environ else 0);open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('ok')"]
        # Missing HOME is not synthesized or inherited; the command itself decides whether it requires HOME.
        observed=os.path.join(self.workspace,"observed-home"); missing["execution"]["commands"][0]["argv"]=[PYTHON,"-c","import os;open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write(str(os.environ.get('HOME')))" ]; missing["execution"]["commands"][0]["artifact_path"]=observed
        receipt=campaign.execute_manifest(missing,self.key); self.assertEqual("passed",receipt["constituents"][0]["status"])
        with open(observed,encoding="utf-8") as handle: self.assertEqual("None",handle.read())
        global_home=copy.deepcopy(self.contract); global_home["execution"]["environment"]={"HOME":home}; self.rejects(global_home,"safe controller allowlist")
        outside=copy.deepcopy(self.contract); outside["execution"]["commands"][0]["environment"]["HOME"]=self.temp_root; self.rejects(outside,"escapes workspace")
        link=os.path.join(self.workspace,"home-link"); os.symlink(self.workspace,link); linked=copy.deepcopy(self.contract); linked["execution"]["commands"][0]["environment"]["HOME"]=link; self.rejects(linked,"absolute canonical path")

    def test_one_constituent_resume_is_exact_and_in_progress_refuses_rerun(self):
        first={"id":"first","argv":[PYTHON,"-c","import os;open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('a')"],"cwd":self.workspace,"coverage_units":["a"],"artifact_path":os.path.join(self.workspace,"a")}
        second={"id":"second","argv":[PYTHON,"-c","import os;open(os.environ['OUROBOROS_CAMPAIGN_ARTIFACT'],'w').write('b')"],"cwd":self.workspace,"coverage_units":["b"],"artifact_path":os.path.join(self.workspace,"b"),"requires":["first"]}
        manifest=self.make_manifest(commands=[first,second]); progress=[]; partial=campaign.execute_manifest(manifest,self.key,command_id="first",progress=progress.append)
        self.assertEqual(["first"],[item["command_id"] for item in partial["constituents"]]); self.assertEqual("missing",campaign.adjudicate(manifest,partial,self.key)["classification"]); self.assertEqual("in_progress",progress[0]["constituents"][0]["status"])
        resumed=campaign.execute_manifest(manifest,self.key,reuse=partial,command_id="second",progress=progress.append); self.assertEqual(["first","second"],[item["command_id"] for item in resumed["constituents"]]); self.assertEqual("passed",campaign.adjudicate(manifest,resumed,self.key)["classification"])
        self.assertEqual(partial["invocation_id"],resumed["invocation_id"]); self.assertEqual(progress[0]["invocation_id"],partial["invocation_id"])
        with self.assertRaisesRegex(campaign.ContractError,"effects are uncertain"): campaign.execute_manifest(manifest,self.key,reuse=progress[0],command_id="first")

    def test_execution_lock_is_manifest_scoped_no_follow_and_exclusive(self):
        fd=campaign._execution_lock(self.key_path,self.contract)
        try:
            with self.assertRaisesRegex(campaign.ContractError,"locked by another"): campaign._execution_lock(self.key_path,self.contract)
            info=os.fstat(fd); self.assertEqual(0o600,stat.S_IMODE(info.st_mode))
        finally: os.close(fd)

    def test_event_graph_taxonomy_boundaries_inclusion_and_exact_accounting(self):
        raw=campaign.load_json(FIXTURE); valid=campaign.validate_events(raw,benchmark()); totals=campaign.telemetry_from_events(valid)
        self.assertEqual(3,len(valid["included_events"])); self.assertEqual(10,totals["tool_calls"]); self.assertEqual(140,totals["input_tokens"]); self.assertEqual(5,totals["cache_read_tokens"])
        only_failed=benchmark(); only_failed["inclusion"]=["child_requests","status:failed"]; valid=campaign.validate_events(raw,only_failed); self.assertEqual(5,campaign.telemetry_from_events(valid)["tool_calls"])

    def test_event_graph_rejects_cycles_action_parents_unknown_actions_and_boundaries(self):
        cases=[]
        raw=campaign.load_json(FIXTURE); raw["events"][1]["parent_id"]="child-request"; cases.append((raw,"rooted"))
        raw=campaign.load_json(FIXTURE); raw["events"][4]={"id":"second-action","kind":"action","status":"passed","parent_id":"supervisor-action","action":"approve","metrics":{}}; cases.append((raw,"parent must be a request"))
        raw=campaign.load_json(FIXTURE); raw["events"][3]["action"]="invented"; cases.append((raw,"taxonomy"))
        raw=campaign.load_json(FIXTURE); raw["events"][0]["boundary"]="wrong"; cases.append((raw,"boundaries"))
        for value, phrase in cases:
            with self.subTest(phrase=phrase):
                with self.assertRaisesRegex(campaign.ContractError,phrase): campaign.validate_events(value,benchmark())

    def test_event_duplicate_conflict_refused(self):
        raw=campaign.load_json(FIXTURE); raw["events"][4]["metrics"]["tool_calls"]=99
        with self.assertRaisesRegex(campaign.ContractError,"conflicting duplicate"): campaign.validate_events(raw,benchmark())

    def test_comparison_requires_independent_receipts_and_canonical_workload(self):
        candidate=self.make_manifest("benchmark",nonce="candidate-nonce-01")
        baseline_workspace=os.path.join(self.temp_root,"baseline-work")
        subprocess.run(["git","clone","-q",self.workspace,baseline_workspace],check=True)
        baseline=copy.deepcopy(candidate); baseline["workspace"]=baseline_workspace
        baseline["execution"]["commands"][0]["cwd"]=baseline_workspace
        baseline["execution"]["commands"][0]["artifact_path"]=os.path.join(baseline_workspace,"one.json")
        permitted=["/workspace","/source/tree_digest","/execution/commands/0/cwd","/execution/commands/0/artifact_path"]
        candidate["benchmark"]["permissible_variant_differences"]=permitted
        baseline["benchmark"]["permissible_variant_differences"]=permitted
        candidate["source"]=campaign.measure_source(candidate); baseline["source"]=campaign.measure_source(baseline)
        cr=self.execute(candidate); br=self.execute(baseline)
        self.assertTrue(campaign.compare_contracts(candidate,baseline,cr,br,self.key)["valid"])
        self.assertFalse(campaign.compare_contracts(candidate,baseline,br,br,self.key)["valid"])
        mutations=[("argv",lambda x:x["execution"]["commands"][0]["argv"].append("different")),("coverage",lambda x:x["coverage"]["exclusions"][0].__setitem__("reason","other")),("source revision",lambda x:x["source"].__setitem__("revision","other")),("executable digest",lambda x:x["execution"]["allowed_executables"][0].__setitem__("sha256","sha256:"+"1"*64))]
        for name, mutate in mutations:
            changed=copy.deepcopy(candidate); mutate(changed)
            with self.subTest(name=name):
                result=campaign.compare_contracts(changed,baseline,cr,br,self.key)
                self.assertFalse(result["valid"])
                self.assertTrue(any("unauthorized workload difference" in reason for reason in result["invalid_reasons"]))

    def test_predeclared_exact_variant_path_is_only_authorized_difference(self):
        baseline=self.make_manifest("benchmark"); candidate=copy.deepcopy(baseline); candidate["benchmark"]["permissible_variant_differences"]=["/execution/commands/0/argv/2"]; baseline["benchmark"]["permissible_variant_differences"]=["/execution/commands/0/argv/2"]; candidate["execution"]["commands"][0]["argv"][2]="open('one.json','w').write('candidate')"
        self.assertFalse(any("unauthorized workload" in x for x in campaign.compare_contracts(candidate,baseline,None,None,self.key)["invalid_reasons"]))
        candidate["execution"]["commands"][0]["cwd"]=os.path.join(self.workspace,"missing")
        self.assertFalse(campaign.compare_contracts(candidate,baseline,None,None,self.key)["valid"])

    def test_receipt_wrong_key_forgery_nonce_freshness_and_replay(self):
        receipt=self.execute(); wrong=b"w"*32; self.assertEqual("inconclusive",campaign.adjudicate(self.contract,receipt,wrong)["classification"])
        forged=copy.deepcopy(receipt); forged["constituents"][0]["status"]="failed"; self.assertEqual("inconclusive",campaign.adjudicate(self.contract,forged,self.key)["classification"])
        swapped=copy.deepcopy(receipt); swapped["nonce"]="other"; campaign.sign_receipt(swapped,self.key); self.assertEqual("inconclusive",campaign.adjudicate(self.contract,swapped,self.key)["classification"])
        self.assertEqual("inconclusive",campaign.adjudicate(self.contract,receipt,self.key,now=receipt["issued_at"]+3601)["classification"])

    def test_receipt_policy_accepts_only_truthful_local_integrity(self):
        value=copy.deepcopy(self.contract); value["receipt_policy"]={"mode":"independent","signer_id":"external-controller","nonce":"independent-nonce-123","max_age_seconds":3600}; self.rejects(value,"unsupported")

    def test_independent_policy_refuses_execution_and_local_receipt_reuse(self):
        local_receipt=self.execute()
        marker=os.path.join(self.workspace,"must-not-execute")
        command={"id":"independent","argv":[PYTHON,"-c","open(%r,'w').write('ran')" % marker],"cwd":self.workspace,"coverage_units":["independent"],"artifact_path":marker}
        contract=self.make_manifest(commands=[command]); contract["receipt_policy"]={"mode":"independent","signer_id":"local-controller","nonce":"independent-nonce-123","max_age_seconds":3600}
        with self.assertRaisesRegex(campaign.ContractError,"unsupported"): campaign.execute_manifest(contract,self.key,reuse=local_receipt)
        self.assertFalse(os.path.exists(marker))
        result=campaign.adjudicate(contract,local_receipt,self.key)
        self.assertEqual("inconclusive",result["classification"]); self.assertFalse(result["reusable"])
        self.assertIn("cannot establish independent provenance",result["reasons"][0])

    def test_cli_independent_policy_fails_closed_before_execution(self):
        marker=os.path.join(self.workspace,"cli-must-not-execute")
        command={"id":"independent","argv":[PYTHON,"-c","open(%r,'w').write('ran')" % marker],"cwd":self.workspace,"coverage_units":["independent"],"artifact_path":marker}
        contract=self.make_manifest(commands=[command]); contract["receipt_policy"]={"mode":"independent","signer_id":"external-controller","nonce":"independent-nonce-123","max_age_seconds":3600}
        manifest_path=os.path.join(self.temp_root,"independent.json")
        with open(manifest_path,"w") as handle: json.dump(contract,handle)
        run=subprocess.run([PYTHON,PROGRAM,"execute-manifest","--manifest",manifest_path,"--receipt-out",os.path.join(self.temp_root,"receipt.json"),"--key-file",self.key_path],text=True,capture_output=True)
        self.assertEqual(2,run.returncode); self.assertIn("supports only local_integrity",run.stdout); self.assertFalse(os.path.exists(marker))

    def test_key_fifo_directory_hardlink_permissions_and_workspace_visibility(self):
        fifo=os.path.join(self.temp_root,"fifo"); os.mkfifo(fifo,0o600)
        for path in (fifo,self.temp_root):
            with self.subTest(path=path):
                with self.assertRaises(campaign.ContractError): campaign.load_key(path)
        alias=os.path.join(self.temp_root,"alias"); os.link(self.key_path,alias)
        with self.assertRaisesRegex(campaign.ContractError,"exactly one link"): campaign.load_key(self.key_path)
        os.unlink(alias); os.chmod(self.key_path,0o644)
        with self.assertRaisesRegex(campaign.ContractError,"permissions"): campaign.load_key(self.key_path)

    def test_cli_rejects_key_output_alias_and_workspace_key(self):
        manifest_path=os.path.join(self.temp_root,"manifest.json")
        with open(manifest_path,"w") as h: json.dump(self.contract,h)
        run=subprocess.run([PYTHON,PROGRAM,"execute-manifest","--manifest",manifest_path,"--receipt-out",self.key_path,"--key-file",self.key_path],text=True,capture_output=True); self.assertEqual(2,run.returncode); self.assertIn("alias",run.stdout)
        workspace_key=os.path.join(self.workspace,"visible.key"); os.link(self.key_path,workspace_key)
        run=subprocess.run([PYTHON,PROGRAM,"execute-manifest","--manifest",manifest_path,"--receipt-out",os.path.join(self.temp_root,"out.json"),"--key-file",workspace_key],text=True,capture_output=True); self.assertEqual(2,run.returncode); self.assertIn("visible inside",run.stdout)

    def test_nonregular_and_hardlinked_artifacts_fail(self):
        fifo=os.path.join(self.workspace,"one.json"); os.mkfifo(fifo)
        receipt=self.execute(); self.assertEqual("inconclusive",receipt["constituents"][0]["status"]); os.unlink(fifo)
        other=os.path.join(self.workspace,"other")
        with open(other,"w") as handle: handle.write("x")
        os.link(other,fifo)
        with self.assertRaisesRegex(campaign.ContractError,"exactly one link"): self.execute()

    def test_ignored_influential_input_invalidates_source(self):
        with open(os.path.join(self.workspace,".gitignore"),"w") as h: h.write("ignored.cfg\n")
        with open(os.path.join(self.workspace,"ignored.cfg"),"w") as h: h.write("one")
        first=campaign.measure_source(self.contract)
        with open(os.path.join(self.workspace,"ignored.cfg"),"w") as h: h.write("two")
        self.assertNotEqual(first,campaign.measure_source(self.contract))

    def test_source_rejects_internal_and_external_directory_symlinks(self):
        internal=os.path.join(self.workspace,"internal-dir"); os.mkdir(internal)
        with open(os.path.join(internal,"config"),"w") as handle: handle.write("internal")
        external=os.path.join(self.temp_root,"external-dir"); os.mkdir(external)
        with open(os.path.join(external,"config"),"w") as handle: handle.write("external")
        for name,target in (("internal-link",internal),("external-link",external)):
            link=os.path.join(self.workspace,name); os.symlink(target,link)
            with self.subTest(name=name):
                with self.assertRaisesRegex(campaign.ContractError,"unsupported non-regular directory entry: %s" % name): campaign.measure_source(self.contract)
            os.unlink(link)

    def test_source_rejects_nonregular_directory_entry(self):
        fifo=os.path.join(self.workspace,"source-fifo"); os.mkfifo(fifo)
        with self.assertRaisesRegex(campaign.ContractError,"unsupported non-regular source entry: source-fifo"): campaign.measure_source(self.contract)

    def test_explicit_source_roots_skip_only_declared_generated_directories(self):
        generated=os.path.join(self.workspace,"generated"); os.mkdir(generated)
        os.symlink("source.txt",os.path.join(generated,"cache-link"))
        self.contract["source"].update(roots=["source.txt"],exclusions=["generated"])
        measured=campaign.measure_source(self.contract)
        self.contract["source"].update(measured)
        self.assertEqual(measured,campaign.measure_source(self.contract))
        receipt=self.execute(self.contract)
        self.assertEqual(self.contract["source"],receipt["source"])
        self.assertEqual("passed",campaign.adjudicate(self.contract,receipt,self.key)["classification"])
        bad=copy.deepcopy(self.contract); bad["source"].update(roots=["."],exclusions=[])
        with self.assertRaisesRegex(campaign.ContractError,"unsupported non-regular source entry: generated/cache-link"):
            campaign.measure_source(bad)

    def test_explicit_source_root_rejects_symlinked_intermediate_component(self):
        outside=os.path.join(self.temp_root,"outside"); os.mkdir(outside)
        with open(os.path.join(outside,"source.txt"),"w") as handle: handle.write("outside")
        os.symlink(outside,os.path.join(self.workspace,"escape"))
        self.contract["source"].update(roots=["escape/source.txt"],exclusions=[])
        with self.assertRaisesRegex(campaign.ContractError,"source root contains a symlink component"):
            campaign.measure_source(self.contract)

    def test_source_and_artifact_swaps_are_detected(self):
        receipt=self.execute(); source=os.path.join(self.workspace,"source.txt"); replacement=os.path.join(self.workspace,"replacement")
        with open(replacement,"w") as handle: handle.write("source\n")
        os.replace(replacement,source)
        self.assertEqual("inconclusive",campaign.adjudicate(self.contract,receipt,self.key)["classification"])
        self.contract=self.make_manifest(); receipt=self.execute(); artifact=self.contract["execution"]["commands"][0]["artifact_path"]; replacement=os.path.join(self.workspace,"replacement")
        with open(replacement,"w") as handle: handle.write("ok")
        os.replace(replacement,artifact)
        self.assertEqual("inconclusive",campaign.adjudicate(self.contract,receipt,self.key)["classification"])

    def test_manifest_change_invalidates_reuse_and_refuses_continuation(self):
        receipt=self.execute(); changed=copy.deepcopy(self.contract); changed["execution"]["requested_deadline_ms"]+=1
        self.assertEqual("inconclusive",campaign.adjudicate(changed,receipt,self.key)["classification"])
        with self.assertRaisesRegex(campaign.ContractError,"structurally eligible"): campaign.execute_manifest(changed,self.key,reuse=receipt)

    def test_telemetry_malformed_nonfinite_unbounded(self):
        for bad in ([],{"tool_calls":True},{"tool_calls":1.5},{"billing":-1},{"billing":math.inf},{"billing":campaign.MAX_TELEMETRY+1},{"unknown":1}):
            with self.subTest(bad=bad):
                with self.assertRaises(campaign.ContractError): campaign.validate_telemetry(bad,"telemetry")

    def test_cli_structured_errors_and_authenticated_receipt(self):
        bad=os.path.join(self.temp_root,"bad.json")
        with open(bad,"w") as handle: handle.write('{"x":1,"x":2}')
        run=subprocess.run([PYTHON,PROGRAM,"validate-manifest","--manifest",bad],text=True,capture_output=True); self.assertEqual(2,run.returncode); self.assertFalse(json.loads(run.stdout)["valid"])
        manifest_path=os.path.join(self.temp_root,"manifest.json"); receipt_path=os.path.join(self.temp_root,"receipt.json")
        with open(manifest_path,"w") as handle: json.dump(self.contract,handle)
        run=subprocess.run([PYTHON,PROGRAM,"execute-manifest","--manifest",manifest_path,"--receipt-out",receipt_path,"--key-file",self.key_path],text=True,capture_output=True); self.assertEqual(0,run.returncode,run.stdout+run.stderr); campaign.validate_receipt(campaign.load_json(receipt_path),self.key,self.contract)
        run=subprocess.run([PYTHON,PROGRAM,"not-a-command"],text=True,capture_output=True); self.assertEqual(2,run.returncode); self.assertFalse(json.loads(run.stdout)["valid"])


if __name__ == "__main__": unittest.main(verbosity=2)
