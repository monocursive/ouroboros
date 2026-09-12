#!/usr/bin/env python3
"""Execute and adjudicate bounded local self-development campaigns.

This is a trusted-controller tool, not a host sandbox. It uses direct argv,
pinned executable file descriptors, a replaced allowlisted environment, and
locally authenticated receipts. Cooperative process-group cleanup is not
strong descendant containment.
"""
import argparse
import fcntl
import hashlib
import hmac
import json
import math
import os
import re
import resource
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

MAX_FILE_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 64 * 1_048_576
MAX_PROCESS_FILE_BYTES = 256 * 1_048_576
MAX_OUTPUT_BYTES = 1_048_576
MAX_COMMANDS = 256
MAX_UNITS = 4096
MAX_ARGV = 128
MAX_STRING = 4096
MAX_DEADLINE_MS = 600_000
MAX_CAMPAIGN_DEADLINE_MS = MAX_COMMANDS * MAX_DEADLINE_MS
MAX_EVENTS = 100_000
ARTIFACT_ENV = "OUROBOROS_CAMPAIGN_ARTIFACT"
DECLARED_ENV = "OUROBOROS_CAMPAIGN_DECLARED_ENV"
OUTPUT_OVERFLOW_MARKER = b"\n[OUROBOROS_CAMPAIGN_ARTIFACT_INCOMPLETE: output limit exceeded]\n"
MAX_TELEMETRY = 10**15
STATUSES = {"passed", "failed", "timeout", "inconclusive", "missing", "skipped", "in_progress"}
COUNT_FIELDS = {"tool_calls", "input_tokens", "cache_read_tokens", "output_tokens"}
TELEMETRY_FIELDS = ("tool_calls", "input_tokens", "cache_read_tokens", "output_tokens", "model_active_ms", "approval_wait_ms", "operator_wait_ms", "billing", "user_attention_ms")
BENCHMARK_FIELDS = ("corpus_digest", "scope", "model", "runtime", "environment", "posture", "bounds", "event_boundaries", "action_taxonomy", "inclusion", "permissible_variant_differences")
INCLUSION = {"parent_requests", "child_requests", "actions", "status:passed", "status:failed", "status:refused"}
SAFE_ENV = {"BOOT_GATE_OUT", "CARGO_HOME", "CARGO_NET_OFFLINE", "CARGO_TARGET_DIR", "CI", "HOME", "J2_BOOT_GATE_OUT", "J3_BOOT_GATE_OUT", "LANG", "LC_ALL", "MIX_BUILD_PATH", "MIX_ENV", "MIX_HOME", "NO_COLOR", "OUROBOROS_PROCESS_ID_HELPER", "OUROBOROS_REQUIRE_WASM", "OUROBOROS_SDK_TEST_ROOT", "OUROBOROS_WASM_EXAMPLES_ROOT", "OUROBOROS_WASM_GUEST", "OUROBOROS_WASM_HELPER", "OUROBOROS_WASM_SKEW_DIR", "PATH", "RUSTUP_AUTO_INSTALL", "RUSTUP_HOME", "SHELL", "SOURCE_DATE_EPOCH", "TERM", "TZ"}
COMMAND_PATH_ENV = {"BOOT_GATE_OUT", "CARGO_HOME", "CARGO_TARGET_DIR", "HOME", "J2_BOOT_GATE_OUT", "J3_BOOT_GATE_OUT", "MIX_BUILD_PATH", "MIX_HOME", "OUROBOROS_PROCESS_ID_HELPER", "OUROBOROS_SDK_TEST_ROOT", "OUROBOROS_WASM_EXAMPLES_ROOT", "OUROBOROS_WASM_GUEST", "OUROBOROS_WASM_HELPER", "OUROBOROS_WASM_SKEW_DIR"}
TOOLCHAIN_PATH_ENV = {"RUSTUP_HOME"}
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
VARIANT_PATH = re.compile(r"^/(workspace|source|receipt_policy|execution|coverage)(/[^/~]+|/~[01]|/[0-9]+)*$")


class ContractError(ValueError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def _fd_digest(fd: int) -> str:
    h = hashlib.sha256(); os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, 65536)
        if not block: break
        h.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return "sha256:" + h.hexdigest()


def _open_regular(path: str, name: str, maximum: int, owner: bool = True, single_link: bool = True) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try: fd = os.open(path, flags)
    except OSError as exc: raise ContractError("%s cannot be opened safely: %s" % (name, exc))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode): raise ContractError("%s must be a regular file" % name)
        if owner and info.st_uid != os.geteuid(): raise ContractError("%s must be owned by the effective user" % name)
        if single_link and info.st_nlink != 1: raise ContractError("%s must have exactly one link" % name)
        if info.st_size > maximum: raise ContractError("%s exceeds %d bytes" % (name, maximum))
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino): raise ContractError("%s identity changed while opening" % name)
        return fd, info
    except Exception:
        os.close(fd); raise


def file_digest(path: str) -> str:
    fd, _ = _open_regular(path, "file", max(MAX_ARTIFACT_BYTES, MAX_FILE_BYTES), owner=False, single_link=False)
    try: return _fd_digest(fd)
    finally: os.close(fd)


def _no_duplicates(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result: raise ContractError("duplicate JSON key: %s" % key)
        result[key] = value
    return result


def load_json(path: str) -> Any:
    canonical_path(path, "JSON file", must_exist=True)
    fd, _ = _open_regular(path, "JSON file", MAX_FILE_BYTES)
    try:
        data = b""
        while len(data) <= MAX_FILE_BYTES:
            block = os.read(fd, min(65536, MAX_FILE_BYTES + 1 - len(data)))
            if not block: break
            data += block
        if len(data) > MAX_FILE_BYTES: raise ContractError("JSON document exceeds %d bytes" % MAX_FILE_BYTES)
        return json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=lambda value: (_ for _ in ()).throw(ContractError("non-finite JSON number: %s" % value)))
    finally: os.close(fd)


def obj(value: Any, name: str, required: set, optional: set = frozenset()) -> dict:
    if not isinstance(value, dict): raise ContractError("%s must be an object" % name)
    unknown, missing = set(value) - required - optional, required - set(value)
    if unknown: raise ContractError("%s has unknown keys: %s" % (name, ", ".join(sorted(unknown))))
    if missing: raise ContractError("%s is missing keys: %s" % (name, ", ".join(sorted(missing))))
    return value


def text(value: Any, name: str, maximum: int = MAX_STRING) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > maximum: raise ContractError("%s must be a non-empty NUL-free string of at most %d characters" % (name, maximum))
    return value


def sha256(value: Any, name: str) -> str:
    value = text(value, name)
    if not SHA256.fullmatch(value): raise ContractError("%s must be a canonical SHA-256 digest" % name)
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high: raise ContractError("%s must be an integer from %d through %d" % (name, low, high))
    return value


def string_list(value: Any, name: str, maximum: int, allow_empty: bool = False, unique: bool = True) -> list:
    if not isinstance(value, list) or (not allow_empty and not value) or len(value) > maximum: raise ContractError("%s must be a%s list with at most %d entries" % (name, " non-empty" if not allow_empty else "", maximum))
    result = [text(item, "%s[]" % name) for item in value]
    if unique and len(set(result)) != len(result): raise ContractError("%s contains duplicates" % name)
    return result


def canonical_path(value: Any, name: str, workspace: str | None = None, must_exist: bool = False) -> str:
    path = text(value, name)
    if not os.path.isabs(path) or os.path.normpath(path) != path or os.path.realpath(path) != path: raise ContractError("%s must be an absolute canonical path (symlinks are not accepted)" % name)
    if workspace is not None:
        try: inside = os.path.commonpath((workspace, path)) == workspace
        except ValueError: inside = False
        if not inside: raise ContractError("%s escapes workspace" % name)
    if must_exist and not os.path.exists(path): raise ContractError("%s does not exist" % name)
    return path


def validate_benchmark(value: Any) -> dict:
    bench = obj(value, "benchmark", set(BENCHMARK_FIELDS))
    sha256(bench["corpus_digest"], "benchmark.corpus_digest")
    for field in ("scope", "model", "runtime", "environment", "posture"): text(bench[field], "benchmark.%s" % field)
    bounds = obj(bench["bounds"], "benchmark.bounds", {"tool_calls", "turns", "deadline_ms"})
    integer(bounds["tool_calls"], "benchmark.bounds.tool_calls", 1, 100000); integer(bounds["turns"], "benchmark.bounds.turns", 1, 100000); integer(bounds["deadline_ms"], "benchmark.bounds.deadline_ms", 1, MAX_DEADLINE_MS)
    boundaries = obj(bench["event_boundaries"], "benchmark.event_boundaries", {"start", "terminal"})
    text(boundaries["start"], "benchmark.event_boundaries.start"); text(boundaries["terminal"], "benchmark.event_boundaries.terminal")
    string_list(bench["action_taxonomy"], "benchmark.action_taxonomy", 256)
    inclusion = set(string_list(bench["inclusion"], "benchmark.inclusion", len(INCLUSION)))
    if not inclusion <= INCLUSION or not inclusion & {"parent_requests", "child_requests", "actions"} or not inclusion & {"status:passed", "status:failed", "status:refused"}: raise ContractError("benchmark.inclusion uses an invalid or empty class/status policy")
    variants = string_list(bench["permissible_variant_differences"], "benchmark.permissible_variant_differences", 256, allow_empty=True)
    for path in variants:
        if not VARIANT_PATH.fullmatch(path): raise ContractError("invalid permissible variant path: %s" % path)
    return bench


def validate_receipt_policy(value: Any) -> dict:
    policy = obj(value, "receipt_policy", {"mode", "signer_id", "nonce", "max_age_seconds"})
    if policy["mode"] != "local_integrity": raise ContractError("receipt_policy.mode is unsupported; this runner supports only local_integrity")
    text(policy["signer_id"], "receipt_policy.signer_id", 128); text(policy["nonce"], "receipt_policy.nonce", 256)
    integer(policy["max_age_seconds"], "receipt_policy.max_age_seconds", 1, 86400)
    return policy


def validate_manifest(document: Any) -> dict:
    manifest = obj(document, "manifest", {"schema_version", "mode", "workspace", "source", "receipt_policy", "execution", "coverage"}, {"benchmark"})
    if manifest["schema_version"] != 2: raise ContractError("manifest.schema_version must be 2")
    if manifest["mode"] not in ("validation", "benchmark"): raise ContractError("manifest.mode must be validation or benchmark")
    workspace = canonical_path(manifest["workspace"], "manifest.workspace", must_exist=True)
    if not os.path.isdir(workspace): raise ContractError("manifest.workspace must be a directory")
    source = obj(manifest["source"], "manifest.source", {"revision", "tree_digest"}, {"roots", "exclusions"}); text(source["revision"], "manifest.source.revision"); sha256(source["tree_digest"], "manifest.source.tree_digest")
    roots = string_list(source.get("roots", ["."]), "manifest.source.roots", MAX_UNITS)
    exclusions = string_list(source.get("exclusions", []), "manifest.source.exclusions", MAX_UNITS, allow_empty=True)
    for label, paths in (("root", roots), ("exclusion", exclusions)):
        for path in paths:
            if path == "" or os.path.isabs(path) or path != os.path.normpath(path) or path == ".." or path.startswith("../"):
                raise ContractError("manifest.source.%s must be normalized workspace-relative paths" % label)
    if len(set(roots)) != len(roots) or len(set(exclusions)) != len(exclusions): raise ContractError("duplicate source root or exclusion")
    if any(root == excluded or root.startswith(excluded + os.sep) for root in roots for excluded in exclusions): raise ContractError("source root cannot be excluded")
    validate_receipt_policy(manifest["receipt_policy"])
    execution = obj(manifest["execution"], "manifest.execution", {"environment", "environment_policy", "start_mode", "outer_sandbox", "containment", "requested_deadline_ms", "effective_deadline_ms", "allowed_executables", "commands"})
    if execution["environment_policy"] != "trusted_controller_allowlist_v1": raise ContractError("environment_policy must be trusted_controller_allowlist_v1")
    environment = execution["environment"]
    common_safe_env = SAFE_ENV - COMMAND_PATH_ENV - {"MIX_ENV", "OUROBOROS_REQUIRE_WASM", "SHELL"}
    if not isinstance(environment, dict) or len(environment) > len(common_safe_env): raise ContractError("manifest.execution.environment must be a bounded object")
    for key, value in environment.items():
        if not isinstance(key, str) or not ENV_NAME.fullmatch(key) or key not in common_safe_env: raise ContractError("environment key is not in the safe controller allowlist: %s" % key)
        if not isinstance(value, str) or "\x00" in value or len(value) > MAX_STRING: raise ContractError("environment values must be bounded NUL-free strings")
    if execution["start_mode"] not in ("clean", "existing"): raise ContractError("manifest.execution.start_mode must be clean or existing")
    if execution["outer_sandbox"] not in ("required", "forbidden"): raise ContractError("manifest.execution.outer_sandbox must be required or forbidden")
    containment = obj(execution["containment"], "manifest.execution.containment", {"required"})
    if containment["required"] not in ("cooperative_pgid", "strong_descendants"): raise ContractError("containment.required is invalid")
    requested = integer(execution["requested_deadline_ms"], "requested_deadline_ms", 1, MAX_CAMPAIGN_DEADLINE_MS); effective = integer(execution["effective_deadline_ms"], "effective_deadline_ms", 1, MAX_CAMPAIGN_DEADLINE_MS)
    if effective > requested: raise ContractError("effective_deadline_ms cannot exceed requested_deadline_ms")
    allowed = execution["allowed_executables"]
    if not isinstance(allowed, list) or not allowed or len(allowed) > MAX_COMMANDS: raise ContractError("allowed_executables must be a non-empty bounded list")
    executable_map = {}
    for index, raw in enumerate(allowed):
        item = obj(raw, "allowed_executable[%d]" % index, {"path", "sha256", "env_allowlist"})
        path = canonical_path(item["path"], "allowed_executable.path", must_exist=True)
        if path in executable_map: raise ContractError("duplicate allowed executable")
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK): raise ContractError("allowed executable must be an executable regular file")
        sha256(item["sha256"], "allowed_executable.sha256")
        env_allowlist = set(string_list(item["env_allowlist"], "allowed_executable.env_allowlist", len(SAFE_ENV), allow_empty=True))
        if not env_allowlist <= SAFE_ENV: raise ContractError("executable environment allowlist contains unsafe authority")
        executable_map[path] = env_allowlist
    commands = execution["commands"]
    if not isinstance(commands, list) or not commands or len(commands) > MAX_COMMANDS: raise ContractError("commands must be a non-empty list of at most %d entries" % MAX_COMMANDS)
    command_ids, declared_units, artifact_paths = set(), set(), set()
    for index, raw in enumerate(commands):
        command = obj(raw, "command[%d]" % index, {"id", "argv", "cwd", "coverage_units", "artifact_path"}, {"environment", "deadline_ms", "requires", "artifact_mode"})
        command_id = text(command["id"], "command.id", 256)
        if command_id in command_ids: raise ContractError("duplicate command id: %s" % command_id)
        argv = string_list(command["argv"], "command.argv", MAX_ARGV, unique=False)
        executable = canonical_path(argv[0], "command.argv[0]", must_exist=True)
        if executable not in executable_map: raise ContractError("command executable is not allowed")
        command_environment = command.get("environment", {})
        if not isinstance(command_environment, dict) or len(command_environment) > len(SAFE_ENV): raise ContractError("command.environment must be a bounded object")
        for key, value in command_environment.items():
            if not isinstance(key, str) or not ENV_NAME.fullmatch(key) or key not in SAFE_ENV: raise ContractError("command environment key is not in the safe controller allowlist: %s" % key)
            if not isinstance(value, str) or "\x00" in value or len(value) > MAX_STRING: raise ContractError("command environment values must be bounded NUL-free strings")
            if key == "SHELL": canonical_path(value, "command.environment.SHELL", must_exist=True)
            if key in COMMAND_PATH_ENV: canonical_path(value, "command.environment.%s" % key, workspace)
            if key in TOOLCHAIN_PATH_ENV:
                path = canonical_path(value, "command.environment.%s" % key, must_exist=True)
                if not os.path.isdir(path): raise ContractError("command.environment.%s must be a directory" % key)
        denied = (set(environment) | set(command_environment)) - executable_map[executable]
        if denied: raise ContractError("environment is not allowed for executable %s: %s" % (executable, ", ".join(sorted(denied))))
        if "deadline_ms" in command: integer(command["deadline_ms"], "command.deadline_ms", 1, MAX_DEADLINE_MS)
        requires = string_list(command.get("requires", []), "command.requires", MAX_COMMANDS, allow_empty=True)
        unknown_requirements = set(requires) - command_ids
        if unknown_requirements: raise ContractError("command requirements must name earlier commands: %s" % ", ".join(sorted(unknown_requirements)))
        if command.get("artifact_mode", "declared") not in ("declared", "stdout"): raise ContractError("command.artifact_mode must be declared or stdout")
        command_ids.add(command_id)
        cwd = canonical_path(command["cwd"], "command.cwd", workspace, must_exist=True)
        if not os.path.isdir(cwd): raise ContractError("command.cwd must be a directory")
        units = string_list(command["coverage_units"], "command.coverage_units", MAX_UNITS); overlap = declared_units.intersection(units)
        if overlap: raise ContractError("coverage units assigned more than once: %s" % ", ".join(sorted(overlap)))
        declared_units.update(units); artifact = canonical_path(command["artifact_path"], "command.artifact_path", workspace)
        if artifact in artifact_paths: raise ContractError("artifact paths must be unique")
        artifact_paths.add(artifact)
    coverage = obj(manifest["coverage"], "manifest.coverage", {"required_units", "exclusions"}); required = set(string_list(coverage["required_units"], "coverage.required_units", MAX_UNITS))
    exclusions = coverage["exclusions"]
    if not isinstance(exclusions, list) or len(exclusions) > MAX_UNITS: raise ContractError("coverage.exclusions must be a bounded list")
    excluded = set()
    for index, raw in enumerate(exclusions):
        exclusion = obj(raw, "exclusion[%d]" % index, {"unit", "reason"}); unit = text(exclusion["unit"], "exclusion.unit"); text(exclusion["reason"], "exclusion.reason")
        if unit in excluded: raise ContractError("duplicate exclusion: %s" % unit)
        excluded.add(unit)
    if not excluded <= required or declared_units != required - excluded: raise ContractError("incomplete coverage or invalid exclusions")
    if manifest["mode"] == "benchmark":
        if "benchmark" not in manifest: raise ContractError("benchmark mode requires benchmark metadata")
        validate_benchmark(manifest["benchmark"])
    elif "benchmark" in manifest: raise ContractError("validation mode must not include benchmark metadata")
    return manifest


def validate_telemetry(value: Any, name: str) -> dict:
    telemetry = obj(value, name, set(), set(TELEMETRY_FIELDS))
    for field, item in telemetry.items():
        if item is None: continue
        if isinstance(item, bool) or not isinstance(item, (int, float)) or not math.isfinite(item) or item < 0 or item > MAX_TELEMETRY: raise ContractError("%s.%s must be null or a finite bounded non-negative number" % (name, field))
        if field in COUNT_FIELDS and not isinstance(item, int): raise ContractError("%s.%s must be an integer" % (name, field))
    return telemetry


def _included(event: dict, inclusion: set[str]) -> bool:
    if event["kind"] == "boundary": return False
    category = "actions" if event["kind"] == "action" else ("parent_requests" if event.get("parent_id") is None else "child_requests")
    return category in inclusion and "status:" + event["status"] in inclusion


def validate_events(document: Any, benchmark: dict) -> dict:
    envelope = obj(document, "events document", {"invocation_id", "events"}); invocation = text(envelope["invocation_id"], "events.invocation_id", 256)
    events = envelope["events"]
    if not isinstance(events, list) or not events or len(events) > MAX_EVENTS: raise ContractError("events document must contain a non-empty bounded events list")
    unique, ordered = {}, []
    for index, raw in enumerate(events):
        event = obj(raw, "event[%d]" % index, {"id", "kind", "status", "metrics"}, {"parent_id", "action", "boundary"})
        event_id = text(event["id"], "event.id", 256)
        if event["kind"] not in ("boundary", "request", "action") or event["status"] not in ("passed", "failed", "refused"): raise ContractError("event kind or status is invalid")
        validate_telemetry(event["metrics"], "event.metrics")
        if event["kind"] == "boundary":
            if set(event) != {"id", "kind", "status", "metrics", "boundary"} or event["status"] != "passed" or event["metrics"]: raise ContractError("boundary event has invalid fields")
            text(event["boundary"], "event.boundary", 256)
        elif event["kind"] == "request":
            if "action" in event or "boundary" in event: raise ContractError("request event has invalid fields")
            if event.get("parent_id") is not None: text(event["parent_id"], "event.parent_id", 256)
        else:
            if "boundary" in event: raise ContractError("action event cannot contain boundary")
            text(event.get("action"), "event.action", 256); text(event.get("parent_id"), "event.parent_id", 256)
            if event["action"] not in benchmark["action_taxonomy"]: raise ContractError("event action is outside benchmark taxonomy: %s" % event["action"])
        if event_id in unique:
            if unique[event_id] != event: raise ContractError("conflicting duplicate event id: %s" % event_id)
            continue
        unique[event_id] = event; ordered.append(event)
    boundaries = benchmark["event_boundaries"]
    if ordered[0].get("boundary") != boundaries["start"] or ordered[-1].get("boundary") != boundaries["terminal"]: raise ContractError("events are outside declared start/terminal boundaries")
    if sum(e.get("boundary") == boundaries["start"] for e in ordered) != 1 or sum(e.get("boundary") == boundaries["terminal"] for e in ordered) != 1: raise ContractError("event boundaries must occur exactly once")
    roots = 0; seen = {ordered[0]["id"]}
    for event in ordered[1:-1]:
        if event["kind"] == "boundary": raise ContractError("unexpected interior boundary")
        parent = event.get("parent_id")
        if event["kind"] == "request" and parent is None: roots += 1
        else:
            if parent not in seen: raise ContractError("event graph is not rooted, ordered, and acyclic")
            if unique[parent]["kind"] != "request": raise ContractError("event parent must be a request")
        seen.add(event["id"])
    if roots != 1: raise ContractError("event graph must have exactly one root request")
    inclusion = set(benchmark["inclusion"])
    return {"invocation_id": invocation, "events": ordered, "included_events": [e for e in ordered if _included(e, inclusion)]}


def telemetry_from_events(validated: dict) -> dict:
    totals = {field: None for field in TELEMETRY_FIELDS}
    for event in validated["included_events"]:
        for field, value in event["metrics"].items():
            if value is not None:
                totals[field] = value if totals[field] is None else totals[field] + value
                if totals[field] > MAX_TELEMETRY: raise ContractError("telemetry total exceeds bound")
    return totals


def effective_conditions(manifest: dict) -> dict:
    execution = manifest["execution"]
    return {"conditions_version": 3, "workload_digest": digest({k: manifest[k] for k in ("workspace", "source", "execution", "coverage")}), "environment": execution["environment"], "command_environments": {command["id"]: command.get("environment", {}) for command in execution["commands"]}, "command_deadlines_ms": {command["id"]: min(MAX_DEADLINE_MS, command.get("deadline_ms", MAX_DEADLINE_MS)) for command in execution["commands"]}, "resource_limits": {"process_file_bytes": MAX_PROCESS_FILE_BYTES, "captured_output_bytes": MAX_OUTPUT_BYTES, "receipt_artifact_bytes": MAX_ARTIFACT_BYTES}, "environment_policy": execution["environment_policy"], "start_mode": execution["start_mode"], "outer_sandbox": execution["outer_sandbox"], "effective_deadline_ms": execution["effective_deadline_ms"], "platform": {"system": sys.platform, "machine": os.uname().machine}, "executables": [{"path": x["path"], "sha256": x["sha256"]} for x in execution["allowed_executables"]], "containment": {"required": execution["containment"]["required"], "effective": "cooperative_pgid", "evidence_scope": "cooperative process-group signalling only; not clean-host or strong descendant containment"}}


def _git(workspace: str, args: list) -> bytes:
    try: run = subprocess.run(["git", "-C", workspace] + args, env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc: raise ContractError("cannot measure git source: %s" % exc)
    if run.returncode: raise ContractError("cannot measure git source: %s" % run.stderr.decode(errors="replace")[:300])
    return run.stdout


def _source_paths(manifest: dict) -> list[tuple[bytes, str]]:
    workspace = manifest["workspace"]
    excluded = {item["artifact_path"] for item in manifest["execution"]["commands"]}
    result = []
    roots = manifest["source"].get("roots", ["."])
    excluded_rel = set(manifest["source"].get("exclusions", []))
    seen = set()
    for source_root in roots:
      absolute_root = os.path.normpath(os.path.join(workspace, source_root))
      cursor = workspace
      for component in source_root.split(os.sep):
        if component == ".": continue
        cursor = os.path.join(cursor, component)
        component_info = os.stat(cursor, follow_symlinks=False)
        if stat.S_ISLNK(component_info.st_mode): raise ContractError("source root contains a symlink component: %s" % source_root)
      root_info = os.stat(absolute_root, follow_symlinks=False)
      if os.path.islink(absolute_root) or not (stat.S_ISDIR(root_info.st_mode) or stat.S_ISREG(root_info.st_mode)): raise ContractError("source root is not a regular file or directory: %s" % source_root)
      if stat.S_ISREG(root_info.st_mode):
        walks = [(os.path.dirname(absolute_root), [], [os.path.basename(absolute_root)])]
      else:
        walks = os.walk(absolute_root, topdown=True, followlinks=False)
      for root, dirs, files in walks:
        kept_dirs = []
        for name in sorted(dirs):
            path = os.path.join(root, name); rel = os.path.relpath(path, workspace)
            if rel in excluded_rel: continue
            info = os.stat(path, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode): raise ContractError("source contains unsupported non-regular directory entry: %s" % rel)
            if not (root == workspace and name == ".git"): kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(files):
            path = os.path.join(root, name)
            if root == workspace and name == ".git": continue
            if path in excluded: continue
            rel = os.path.relpath(path, workspace)
            if rel in excluded_rel or rel in seen: continue
            try: raw = rel.encode("utf-8")
            except UnicodeEncodeError: raise ContractError("source path is not UTF-8")
            info = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode): raise ContractError("source contains unsupported non-regular source entry: %s" % rel)
            result.append((raw, path))
            seen.add(rel)
    return sorted(result)


def measure_source(manifest: dict) -> dict:
    workspace = manifest["workspace"]; revision = _git(workspace, ["rev-parse", "HEAD"]).decode().strip(); h = hashlib.sha256()
    for raw, path in _source_paths(manifest):
        if os.path.islink(path): raise ContractError("source contains unsupported non-regular path: %s" % raw.decode())
        fd, info = _open_regular(path, "source file", MAX_ARTIFACT_BYTES)
        try:
            # The local snapshot policy binds both bytes and the opened object's
            # identity. Replacing an input with byte-identical content is still a
            # source transition and invalidates evidence.
            h.update(len(raw).to_bytes(8, "big")); h.update(raw)
            h.update(info.st_dev.to_bytes(8, "big", signed=False)); h.update(info.st_ino.to_bytes(8, "big", signed=False))
            h.update(bytes.fromhex(_fd_digest(fd)[7:]))
        finally: os.close(fd)
    return {"revision": revision, "tree_digest": "sha256:" + h.hexdigest()}


def measured_source_matches(manifest: dict) -> bool:
    measured = measure_source(manifest)
    return all(manifest["source"].get(key) == value for key, value in measured.items())


def _receipt_payload(receipt: dict) -> dict: return {key: value for key, value in receipt.items() if key != "authentication"}


def load_key(path: str) -> bytes:
    canonical_path(path, "key file", must_exist=True); fd, info = _open_regular(path, "key file", 64)
    try:
        if stat.S_IMODE(info.st_mode) & 0o077: raise ContractError("key file permissions must deny group/other access")
        key = os.read(fd, 65)
    finally: os.close(fd)
    if len(key) < 32 or len(key) > 64: raise ContractError("key file must contain 32 through 64 bytes")
    return key


def sign_receipt(receipt: dict, key: bytes) -> None:
    signature = hmac.new(key, canonical(_receipt_payload(receipt)).encode(), hashlib.sha256).hexdigest()
    receipt["authentication"] = {"scheme": "hmac-sha256-local-v2", "key_id": "sha256:" + hashlib.sha256(key).hexdigest(), "signature": signature}


def validate_receipt(document: Any, key: bytes | None = None, manifest: dict | None = None, now: int | None = None) -> dict:
    receipt = obj(document, "receipt", {"schema_version", "manifest_digest", "source", "invocation_id", "issued_at", "signer_id", "nonce", "effective_conditions", "constituents", "telemetry", "events_digest", "authentication"})
    if receipt["schema_version"] != 2: raise ContractError("receipt.schema_version must be 2")
    sha256(receipt["manifest_digest"], "receipt.manifest_digest"); source = obj(receipt["source"], "receipt.source", {"revision", "tree_digest"}, {"roots", "exclusions"}); text(source["revision"], "receipt.source.revision"); sha256(source["tree_digest"], "receipt.source.tree_digest")
    if "roots" in source: string_list(source["roots"], "receipt.source.roots", MAX_UNITS)
    if "exclusions" in source: string_list(source["exclusions"], "receipt.source.exclusions", MAX_UNITS, allow_empty=True)
    text(receipt["invocation_id"], "receipt.invocation_id", 256); integer(receipt["issued_at"], "receipt.issued_at", 0, 2**63 - 1); text(receipt["signer_id"], "receipt.signer_id", 128); text(receipt["nonce"], "receipt.nonce", 256)
    if not isinstance(receipt["effective_conditions"], dict): raise ContractError("receipt.effective_conditions must be an object")
    validate_telemetry(receipt["telemetry"], "receipt.telemetry")
    if receipt["events_digest"] is not None: sha256(receipt["events_digest"], "receipt.events_digest")
    constituents = receipt["constituents"]
    if not isinstance(constituents, list) or len(constituents) > MAX_COMMANDS: raise ContractError("receipt.constituents must be a bounded list")
    seen = set()
    for index, raw in enumerate(constituents):
        item = obj(raw, "constituent[%d]" % index, {"command_id", "status", "coverage_units", "artifact", "exit_code", "resolved_executable", "executable_digest", "executable_identity", "elapsed_ms", "output_digest", "output_truncated"})
        command_id = text(item["command_id"], "constituent.command_id", 256)
        if command_id in seen: raise ContractError("duplicate constituent command_id")
        seen.add(command_id)
        if item["status"] not in STATUSES: raise ContractError("constituent.status is invalid")
        string_list(item["coverage_units"], "constituent.coverage_units", MAX_UNITS, allow_empty=True)
        if item["exit_code"] is not None: integer(item["exit_code"], "constituent.exit_code", -255, 255)
        text(item["resolved_executable"], "constituent.resolved_executable"); sha256(item["executable_digest"], "constituent.executable_digest")
        identity = obj(item["executable_identity"], "constituent.executable_identity", {"device", "inode"}); integer(identity["device"], "device", 0, 2**63 - 1); integer(identity["inode"], "inode", 0, 2**63 - 1)
        integer(item["elapsed_ms"], "constituent.elapsed_ms", 0, MAX_DEADLINE_MS + 5000); sha256(item["output_digest"], "constituent.output_digest")
        if not isinstance(item["output_truncated"], bool): raise ContractError("output_truncated must be boolean")
        if item["artifact"] is not None:
            artifact = obj(item["artifact"], "constituent.artifact", {"path", "sha256", "bytes", "identity"}); text(artifact["path"], "artifact.path"); sha256(artifact["sha256"], "artifact.sha256"); integer(artifact["bytes"], "artifact.bytes", 0, MAX_ARTIFACT_BYTES); identity = obj(artifact["identity"], "artifact.identity", {"device", "inode"}); integer(identity["device"], "device", 0, 2**63 - 1); integer(identity["inode"], "inode", 0, 2**63 - 1)
    auth = obj(receipt["authentication"], "receipt.authentication", {"scheme", "key_id", "signature"})
    if auth["scheme"] != "hmac-sha256-local-v2": raise ContractError("unsupported receipt authentication")
    sha256(auth["key_id"], "receipt.authentication.key_id"); text(auth["signature"], "receipt.authentication.signature")
    if key is None: raise ContractError("receipt authentication key is required")
    if auth["key_id"] != "sha256:" + hashlib.sha256(key).hexdigest(): raise ContractError("receipt authentication key ID differs")
    expected = hmac.new(key, canonical(_receipt_payload(receipt)).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, auth["signature"]): raise ContractError("receipt authentication failed")
    if manifest is not None:
        policy = manifest["receipt_policy"]
        if receipt["signer_id"] != policy["signer_id"] or receipt["nonce"] != policy["nonce"]: raise ContractError("receipt signer or nonce differs")
        current = int(time.time()) if now is None else now
        if receipt["issued_at"] > current + 5 or current - receipt["issued_at"] > policy["max_age_seconds"]: raise ContractError("receipt is outside its freshness window")
    return receipt


def _stable_file(path: str, name: str, maximum: int) -> tuple[dict, int]:
    fd, info = _open_regular(path, name, maximum)
    return ({"path": path, "sha256": _fd_digest(fd), "bytes": info.st_size, "identity": {"device": info.st_dev, "inode": info.st_ino}}, fd)


def _receipt_assessment(manifest: dict, receipt: dict | None, key: bytes | None = None, verify_live: bool = True, now: int | None = None) -> dict:
    result = {"classification": "missing", "reusable": False, "manifest_digest": digest(manifest), "reasons": [], "continuation_eligible": False, "passing_constituents": [], "uncertain_effect": False}
    if manifest.get("receipt_policy", {}).get("mode") != "local_integrity":
        result["classification"] = "inconclusive"; result["reasons"].append("receipt_policy.mode is unsupported; local HMAC receipts cannot establish independent provenance"); return result
    if receipt is None: result["reasons"].append("receipt is absent"); return result
    try: validate_receipt(receipt, key, manifest, now)
    except ContractError as exc: result["classification"] = "inconclusive"; result["reasons"].append(str(exc)); return result
    if receipt["manifest_digest"] != result["manifest_digest"] or receipt["source"] != manifest["source"]: result["classification"] = "inconclusive"; result["reasons"].append("receipt source or manifest binding is stale"); return result
    if receipt["effective_conditions"].get("conditions_version") != 3: result["classification"] = "inconclusive"; result["reasons"].append("receipt effective conditions predate version 3 and are intentionally non-reusable; historical command conditions are not inferred"); return result
    if receipt["effective_conditions"] != effective_conditions(manifest): result["classification"] = "inconclusive"; result["reasons"].append("effective execution conditions differ"); return result
    if verify_live:
        try: measured = measure_source(manifest)
        except ContractError as exc: result["classification"] = "inconclusive"; result["reasons"].append(str(exc)); return result
        if any(manifest["source"].get(key) != value for key, value in measured.items()): result["classification"] = "inconclusive"; result["reasons"].append("live source tree changed"); return result
    command_list = manifest["execution"]["commands"]; commands = {item["id"]: item for item in command_list}; constituents = {item["command_id"]: item for item in receipt["constituents"]}
    if set(constituents) - set(commands): result["classification"] = "inconclusive"; result["reasons"].append("receipt has unknown constituents"); return result
    allowed = {item["path"]: item["sha256"] for item in manifest["execution"]["allowed_executables"]}; statuses = []
    for command_id, command in commands.items():
        item = constituents.get(command_id)
        if item is None: statuses.append("missing"); continue
        if item["coverage_units"] != command["coverage_units"] or item["resolved_executable"] != command["argv"][0]: result["classification"] = "inconclusive"; result["reasons"].append("constituent binding differs for %s" % command_id); return result
        try:
            exe_fd, exe_info = _open_regular(command["argv"][0], "executable", MAX_ARTIFACT_BYTES, owner=False, single_link=False)
            exe_digest = _fd_digest(exe_fd); os.close(exe_fd)
        except ContractError as exc: result["classification"] = "inconclusive"; result["reasons"].append(str(exc)); return result
        if item["executable_digest"] != allowed[command["argv"][0]] or exe_digest != allowed[command["argv"][0]] or item["executable_identity"] != {"device": exe_info.st_dev, "inode": exe_info.st_ino}: result["classification"] = "inconclusive"; result["reasons"].append("executable changed for %s" % command_id); return result
        artifact = item["artifact"]
        if item["status"] == "passed":
            try: current, fd = _stable_file(command["artifact_path"], "artifact", MAX_ARTIFACT_BYTES); os.close(fd)
            except ContractError: statuses.append("inconclusive"); continue
            if artifact is None or current != artifact: statuses.append("inconclusive"); continue
        statuses.append(item["status"])
    classification = "failed" if "failed" in statuses else "timeout" if "timeout" in statuses else "inconclusive" if "in_progress" in statuses else "missing" if "missing" in statuses else "inconclusive" if any(x in statuses for x in ("inconclusive", "skipped")) else "passed"
    result["classification"] = classification; result["reusable"] = classification == "passed"
    result["uncertain_effect"] = "in_progress" in statuses
    if classification != "passed": result["reasons"].append("not every required constituent has current passing evidence")
    present_ids = [item["command_id"] for item in receipt["constituents"]]
    expected_order = [command["id"] for command in command_list if command["id"] in constituents]
    dependency_closed = all(all(requirement in constituents and constituents[requirement]["status"] == "passed" for requirement in commands[command_id].get("requires", [])) for command_id in present_ids)
    if receipt["constituents"] and classification in ("passed", "missing") and all(item["status"] == "passed" for item in receipt["constituents"]) and present_ids == expected_order and dependency_closed:
        result["continuation_eligible"] = True; result["passing_constituents"] = list(receipt["constituents"])
    return result


def adjudicate(manifest: dict, receipt: dict | None, key: bytes | None = None, verify_live: bool = True, now: int | None = None) -> dict:
    assessment = _receipt_assessment(manifest, receipt, key, verify_live, now)
    return {key: assessment[key] for key in ("classification", "reusable", "manifest_digest", "reasons")}


def _limit_output() -> None:
    # RLIMIT_FSIZE applies to every regular file the command writes, not only the inherited
    # stdout tempfile. Keep a hard process-level ceiling without preventing bounded tests and
    # build tools from creating legitimate files larger than the captured-output budget.
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_PROCESS_FILE_BYTES, MAX_PROCESS_FILE_BYTES))


def _bounded_output(output) -> tuple[bytes, bool]:
    output.seek(0, os.SEEK_END)
    overflow = output.tell() >= MAX_OUTPUT_BYTES
    output.seek(0)
    data = output.read(MAX_OUTPUT_BYTES)
    if not overflow:
        return data, False
    keep = max(0, MAX_OUTPUT_BYTES - len(OUTPUT_OVERFLOW_MARKER))
    return data[:keep] + OUTPUT_OVERFLOW_MARKER, True


def _terminate_group(process: subprocess.Popen, grace: float) -> None:
    try: os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError: return
    except PermissionError: pass
    try: process.wait(timeout=grace)
    except subprocess.TimeoutExpired: pass
    if grace: time.sleep(grace)
    try: os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError): pass


def _run_command(command: dict, environment: dict, deadline_ms: int, executable_fd: int, executable_info: os.stat_result, executable_digest: str) -> dict:
    executable = command["argv"][0]; started = time.monotonic(); exit_code, status_name = None, "inconclusive"; artifact_path = command["artifact_path"]
    identity = {"device": executable_info.st_dev, "inode": executable_info.st_ino}
    empty = {"command_id": command["id"], "status": "inconclusive", "coverage_units": command["coverage_units"], "artifact": None, "exit_code": None, "resolved_executable": executable, "executable_digest": executable_digest, "executable_identity": identity, "elapsed_ms": 0, "output_digest": digest(""), "output_truncated": False}
    if os.path.lexists(artifact_path):
        try:
            old_fd, _ = _open_regular(artifact_path, "pre-existing artifact", MAX_ARTIFACT_BYTES); os.close(old_fd); os.unlink(artifact_path)
        except ContractError: return empty
    fd_exec_path = executable
    if sys.platform.startswith("linux"):
        candidate = "/proc/self/fd/%d" % executable_fd
        if os.path.exists(candidate): fd_exec_path = candidate
    command_environment = dict(environment)
    command_environment.update(command.get("environment", {}))
    declared_environment = dict(command_environment)
    command_environment[ARTIFACT_ENV] = artifact_path
    command_environment[DECLARED_ENV] = canonical(declared_environment)
    with tempfile.TemporaryFile() as output:
        process = None
        try:
            process = subprocess.Popen(command["argv"], executable=fd_exec_path, pass_fds=(executable_fd,), cwd=command["cwd"], env=command_environment, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, shell=False, start_new_session=True, preexec_fn=_limit_output)
            try: exit_code = process.wait(timeout=deadline_ms / 1000); status_name = "passed" if exit_code == 0 else "failed"; _terminate_group(process, 0.1)
            except subprocess.TimeoutExpired:
                status_name = "timeout"; _terminate_group(process, 1.0)
                try: process.wait(timeout=2)
                except subprocess.TimeoutExpired: status_name = "inconclusive"
            data, truncated = _bounded_output(output)
            if truncated: status_name = "failed"
        except (OSError, subprocess.SubprocessError):
            if process is not None: _terminate_group(process, 0.1)
            data = b""; truncated = False; status_name = "inconclusive"
    artifact = None
    if command.get("artifact_mode", "declared") == "stdout":
        try:
            artifact_fd = os.open(artifact_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                view = memoryview(data)
                while view: view = view[os.write(artifact_fd, view):]
                os.fsync(artifact_fd)
            finally: os.close(artifact_fd)
            artifact, artifact_fd = _stable_file(artifact_path, "artifact", MAX_ARTIFACT_BYTES); os.close(artifact_fd)
        except (OSError, ContractError):
            status_name = "inconclusive"; artifact = None
    if status_name == "passed" and artifact is None:
        try: artifact, artifact_fd = _stable_file(artifact_path, "artifact", MAX_ARTIFACT_BYTES); os.close(artifact_fd)
        except ContractError: status_name = "inconclusive"
    return {"command_id": command["id"], "status": status_name, "coverage_units": command["coverage_units"], "artifact": artifact, "exit_code": exit_code, "resolved_executable": executable, "executable_digest": executable_digest, "executable_identity": identity, "elapsed_ms": min(MAX_DEADLINE_MS + 5000, int((time.monotonic() - started) * 1000)), "output_digest": "sha256:" + hashlib.sha256(data).hexdigest(), "output_truncated": truncated}


def _issue_receipt(manifest: dict, key: bytes, constituents: list[dict], events: dict | None = None, invocation_id: str | None = None) -> dict:
    telemetry = {field: None for field in TELEMETRY_FIELDS} if events is None else telemetry_from_events(events)
    invocation = (secrets.token_hex(16) if invocation_id is None else invocation_id) if events is None else events["invocation_id"]; policy = manifest["receipt_policy"]
    receipt = {"schema_version": 2, "manifest_digest": digest(manifest), "source": manifest["source"], "invocation_id": invocation, "issued_at": int(time.time()), "signer_id": policy["signer_id"], "nonce": policy["nonce"], "effective_conditions": effective_conditions(manifest), "constituents": constituents, "telemetry": telemetry, "events_digest": None if events is None else digest(events["events"]), "authentication": {}}
    sign_receipt(receipt, key); return receipt


def execute_manifest(manifest: dict, key: bytes, reuse: dict | None = None, events: dict | None = None, command_id: str | None = None, progress=None) -> dict:
    validate_manifest(manifest); execution = manifest["execution"]
    if execution["outer_sandbox"] == "required": raise ContractError("required outer sandbox is unavailable in this local runner")
    if execution["containment"]["required"] == "strong_descendants": raise ContractError("strong descendant containment is unavailable; refusing before execution")
    measured = measure_source(manifest)
    if any(manifest["source"].get(key) != value for key, value in measured.items()): raise ContractError("manifest source does not match measured workspace snapshot")
    if execution["start_mode"] == "clean" and _git(manifest["workspace"], ["status", "--porcelain", "--untracked-files=no"]).strip(): raise ContractError("clean start_mode requires a clean tracked worktree")
    executable_fds = {}
    try:
        for item in execution["allowed_executables"]:
            fd, info = _open_regular(item["path"], "allowed executable", MAX_ARTIFACT_BYTES, owner=False, single_link=False); actual = _fd_digest(fd)
            if actual != item["sha256"]: os.close(fd); raise ContractError("allowed executable digest changed: %s" % item["path"])
            executable_fds[item["path"]] = (fd, info, actual)
        reusable = {}
        invocation_id = None
        if reuse is not None:
            previous = _receipt_assessment(manifest, reuse, key)
            if previous["uncertain_effect"]: raise ContractError("prior selected command is in_progress; effects are uncertain and automatic rerun is refused")
            if not previous["continuation_eligible"]: raise ContractError("reuse receipt is not structurally eligible for continuation")
            reusable = {item["command_id"]: item for item in previous["passing_constituents"]}
            invocation_id = reuse["invocation_id"]
        if command_id is not None and command_id not in {item["id"] for item in execution["commands"]}: raise ContractError("selected command id is unknown")
        deadline = time.monotonic() + execution["effective_deadline_ms"] / 1000; constituents = []
        completed = {item_id: "passed" for item_id in reusable}
        for command in execution["commands"]:
            if command["id"] in reusable: constituents.append(reusable[command["id"]]); continue
            remaining = int((deadline - time.monotonic()) * 1000); fd, info, actual = executable_fds[command["argv"][0]]; identity = {"device": info.st_dev, "inode": info.st_ino}
            missing = {requirement for requirement in command.get("requires", []) if completed.get(requirement) != "passed"}
            if command_id is not None and command["id"] != command_id: continue
            if remaining <= 0 or missing: item = {"command_id": command["id"], "status": "missing" if remaining <= 0 else "skipped", "coverage_units": command["coverage_units"], "artifact": None, "exit_code": None, "resolved_executable": command["argv"][0], "executable_digest": actual, "executable_identity": identity, "elapsed_ms": 0, "output_digest": digest(""), "output_truncated": False}
            else:
                if progress is not None:
                    pending = {"command_id": command["id"], "status": "in_progress", "coverage_units": command["coverage_units"], "artifact": None, "exit_code": None, "resolved_executable": command["argv"][0], "executable_digest": actual, "executable_identity": identity, "elapsed_ms": 0, "output_digest": digest(""), "output_truncated": False}
                    if invocation_id is None: invocation_id = secrets.token_hex(16)
                    progress(_issue_receipt(manifest, key, constituents + [pending], events, invocation_id))
                item = _run_command(command, execution["environment"], min(remaining, command.get("deadline_ms", MAX_DEADLINE_MS)), fd, info, actual)
            constituents.append(item); completed[command["id"]] = item["status"]
    finally:
        for fd, _, _ in executable_fds.values(): os.close(fd)
    if not measured_source_matches(manifest): raise ContractError("workspace source snapshot changed during execution")
    return _issue_receipt(manifest, key, constituents, events, invocation_id)


def telemetry_projection(receipt: dict | None) -> dict:
    supplied = {} if not isinstance(receipt, dict) or not isinstance(receipt.get("telemetry"), dict) else receipt["telemetry"]
    return {field: supplied.get(field) for field in TELEMETRY_FIELDS}


def _diff_paths(left: Any, right: Any, path: str = "") -> list[str]:
    if type(left) is not type(right): return [path or "/"]
    if isinstance(left, dict):
        paths = []
        for key in sorted(set(left) | set(right)):
            child = path + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if key not in left or key not in right: paths.append(child)
            else: paths.extend(_diff_paths(left[key], right[key], child))
        return paths
    if isinstance(left, list):
        if len(left) != len(right): return [path]
        return [p for i, (a, b) in enumerate(zip(left, right)) for p in _diff_paths(a, b, path + "/" + str(i))]
    return [] if left == right else [path]


def _workload(manifest: dict) -> dict: return {key: manifest[key] for key in ("workspace", "source", "receipt_policy", "execution", "coverage")}


def compare_contracts(candidate: dict, baseline: dict, candidate_receipt: dict | None, baseline_receipt: dict | None, key: bytes | None) -> dict:
    reasons = []
    for side, manifest in (("candidate", candidate), ("baseline", baseline)):
        try: validate_manifest(manifest)
        except ContractError as exc: reasons.append("%s: %s" % (side, exc))
    if not reasons:
        if candidate["mode"] != "benchmark" or baseline["mode"] != "benchmark": reasons.append("both contracts must be benchmark mode")
        else:
            for field in BENCHMARK_FIELDS:
                if candidate["benchmark"][field] != baseline["benchmark"][field]: reasons.append("benchmark.%s differs" % field)
            permitted = set(candidate["benchmark"]["permissible_variant_differences"])
            for path in _diff_paths(_workload(candidate), _workload(baseline)):
                if path not in permitted: reasons.append("unauthorized workload difference: %s" % path)
    adjudications = {}
    if not reasons:
        for side, manifest, receipt in (("candidate", candidate, candidate_receipt), ("baseline", baseline, baseline_receipt)):
            result = adjudicate(manifest, receipt, key); adjudications[side] = result
            if result["classification"] != "passed": reasons.append("%s receipt is %s" % (side, result["classification"]))
        if candidate_receipt is not None and baseline_receipt is not None and candidate_receipt.get("invocation_id") == baseline_receipt.get("invocation_id"): reasons.append("benchmark samples require independent invocation IDs")
        if candidate["receipt_policy"]["mode"] == "independent" and candidate_receipt is not None and baseline_receipt is not None and candidate_receipt.get("nonce") == baseline_receipt.get("nonce"): reasons.append("independent benchmark samples require distinct controller nonces")
    return {"schema_version": 2, "valid": not reasons, "invalid_reasons": reasons, "adjudications": adjudications, "telemetry": {"candidate": telemetry_projection(candidate_receipt), "baseline": telemetry_projection(baseline_receipt)}}


def emit(value: Any) -> None: sys.stdout.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _identity(path: str) -> tuple[int, int] | None:
    try: info = os.stat(path, follow_symlinks=False); return info.st_dev, info.st_ino
    except FileNotFoundError: return None


def _check_cli_paths(manifest_path: str, key_path: str, output_path: str, manifest: dict, other_paths: list[str]) -> None:
    key_real = canonical_path(key_path, "key file", must_exist=True); workspace = manifest["workspace"]
    if os.path.commonpath((workspace, key_real)) == workspace: raise ContractError("key file must not be visible inside the command workspace")
    key_identity = _identity(key_real)
    paths = [manifest_path, output_path] + other_paths + [c["artifact_path"] for c in manifest["execution"]["commands"]]
    for path in paths:
        if path and _identity(os.path.abspath(path)) == key_identity: raise ContractError("key file must not alias any input, output, or artifact")
    output = os.path.abspath(output_path)
    if os.path.lexists(output):
        fd, _ = _open_regular(output, "receipt output", MAX_FILE_BYTES); os.close(fd)


def _execution_lock(key_path: str, manifest: dict) -> int:
    lock_path = os.path.abspath(key_path) + ".campaign-" + digest(manifest).split(":", 1)[1] + ".lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        info = os.fstat(fd)
        current = os.stat(lock_path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ContractError("execution lock must be an owner-only regular file with stable identity")
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise ContractError("campaign invocation is locked by another execution")
        return fd
    except Exception:
        os.close(fd); raise


def _parse_args(argv: list[str]) -> argparse.Namespace:
    class JSONParser(argparse.ArgumentParser):
        def error(self, message): raise ContractError("argument error: " + message)
    parser = JSONParser(); sub = parser.add_subparsers(dest="command", required=True, parser_class=JSONParser)
    validate = sub.add_parser("validate-manifest"); validate.add_argument("--manifest", required=True); validate.add_argument("--receipt"); validate.add_argument("--key-file")
    execute = sub.add_parser("execute-manifest"); execute.add_argument("--manifest", required=True); execute.add_argument("--receipt-out", required=True); execute.add_argument("--key-file", required=True); execute.add_argument("--reuse-receipt"); execute.add_argument("--events"); execute.add_argument("--command-id")
    compare = sub.add_parser("compare-contract"); compare.add_argument("--candidate-manifest", required=True); compare.add_argument("--baseline-manifest", required=True); compare.add_argument("--candidate-receipt", required=True); compare.add_argument("--baseline-receipt", required=True); compare.add_argument("--key-file", required=True)
    return parser.parse_args(argv)


def main() -> int:
    try:
        args = _parse_args(sys.argv[1:])
        if args.command == "validate-manifest":
            manifest = validate_manifest(load_json(args.manifest)); receipt = load_json(args.receipt) if args.receipt else None; key = load_key(args.key_file) if args.key_file else None
            emit({"schema_version": 2, "valid_manifest": True, "adjudication": adjudicate(manifest, receipt, key)})
        elif args.command == "execute-manifest":
            manifest = validate_manifest(load_json(args.manifest)); _check_cli_paths(args.manifest, args.key_file, args.receipt_out, manifest, [args.reuse_receipt, args.events]); key = load_key(args.key_file); reuse = load_json(args.reuse_receipt) if args.reuse_receipt else None
            events = validate_events(load_json(args.events), manifest["benchmark"]) if args.events and manifest["mode"] == "benchmark" else None
            if args.events and events is None: raise ContractError("events are accepted only for benchmark mode")
            output = os.path.abspath(args.receipt_out); directory = os.path.dirname(output)
            lock_fd = _execution_lock(args.key_file, manifest)
            try:
                def persist(value):
                    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, delete=False) as handle: json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False); handle.write("\n"); temporary = handle.name
                    os.chmod(temporary, 0o600); os.replace(temporary, output)
                receipt = execute_manifest(manifest, key, reuse, events, args.command_id, persist); persist(receipt)
            finally: os.close(lock_fd)
            emit({"schema_version": 2, "receipt": output, "adjudication": adjudicate(manifest, receipt, key)})
        else:
            key = load_key(args.key_file); candidate_receipt = load_json(args.candidate_receipt); baseline_receipt = load_json(args.baseline_receipt)
            emit(compare_contracts(load_json(args.candidate_manifest), load_json(args.baseline_manifest), candidate_receipt, baseline_receipt, key))
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError, ValueError) as exc:
        emit({"schema_version": 2, "valid": False, "error": str(exc)}); return 2
    return 0


if __name__ == "__main__": raise SystemExit(main())
