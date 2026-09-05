#!/usr/bin/env python3
"""Exercise the real ouro binary in a fresh PTY against a local scripted gateway.

Run after `cargo build --manifest-path tui/Cargo.toml`:
    python3 scripts/qa-tui-onboarding.py /tmp/ouro-onboarding-qa

No live account, provider, browser, or user's config is used. This checks terminal input,
OAuth handoff/cancellation/retry, task dispatch, and terminal restoration; it does not
claim to validate the external OAuth service. Evidence is written to the output folder.
"""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import socket
import struct
import sys
import termios
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "tui/target/debug/ouro"
OUTPUT = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/ouro-onboarding-qa")
HELLO = json.loads((ROOT / "test/support/gateway_golden/hello_result.json").read_text())["result"]
ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def run_case(name):
    directory = OUTPUT / name
    directory.mkdir(parents=True, exist_ok=True)
    data = directory / "data"
    data.mkdir(exist_ok=True, mode=0o700)
    token = directory / "token"
    token.write_text("0" * 64)
    token.chmod(0o600)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    address = f"127.0.0.1:{listener.getsockname()[1]}"
    state = {"connected": False, "login": None, "status": "idle", "requests": [], "sessions": [], "error": None}
    stop = threading.Event()
    pid, terminal = pty.fork()
    if pid == 0:
        environment = os.environ.copy()
        environment.update({"TERM": "xterm-256color", "XDG_CONFIG_HOME": str(directory / "config"),
                            "OUROBOROS_DATA_DIR": str(data), "OURO_REDUCED_MOTION": "1"})
        os.chdir(directory)
        os.execve(str(BINARY), [str(BINARY), "attach", "--addr", address, "--token-file", str(token)], environment)
    fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    captured = bytearray()

    def gateway():
        try:
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            with connection, connection.makefile("rb") as reader:
                for raw in reader:
                    request = json.loads(raw)
                    method, params = request["method"], request.get("params", {})
                    state["requests"].append({"method": method, "params": {} if method == "hello" else params})
                    result = {}
                    if method == "hello":
                        result = dict(HELLO, scope="operate", node="ouro@onboarding-qa")
                    elif method == "account.read":
                        result = {"account": {"type": "chatgpt", "planType": "pro"} if state["connected"] else None,
                                  "requiresOpenaiAuth": True,
                                  "login": {"status": state["status"], "loginId": state["login"], "error": state["error"]}}
                    elif method == "account.login.start":
                        count = sum(r["method"] == method for r in state["requests"])
                        state.update(login=f"qa-login-{count}", status="pending", error=None)
                        # A code with no URL ensures this fixture never launches a browser.
                        result = {"loginId": state["login"], "userCode": "QA-1234", "type": "chatgptDeviceCode"}
                    elif method == "account.login.cancel":
                        state.update(status="cancelled")
                    elif method == "interactive.start":
                        if name == "start-refusal" and not state["sessions"] and not state.get("refused"):
                            state["refused"] = True
                            connection.sendall((json.dumps({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32602, "message": "The selected folder is unavailable. Choose another folder in /options."}}) + "\n").encode())
                            continue
                        session = dict(params, status="idle", options={"model": params.get("model")})
                        state["sessions"].append(session)
                        result = {"_struct": "Ouroboros.Interactive.Ref", "id": params["id"]}
                    elif method == "interactive.info":
                        result = state["sessions"][-1]
                    elif method == "interactive.list":
                        result = state["sessions"]
                    elif method.endswith(".list") or method in ("interactive.subscribe", "interactive.replay", "runtime.providers"):
                        result = []
                    elif method == "interactive.send_message":
                        result = {"accepted": True, "turn_id": params["turn_id"]}
                    connection.sendall((json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}) + "\n").encode())
                    if method == "interactive.send_message":
                        for sequence, kind, text in [(1, "input_accepted", params["input"]), (2, "output_text_final", "QA task completed. Your first conversation is ready.")]:
                            event = {"jsonrpc": "2.0", "method": "interactive.event", "params": {"id": params["id"], "event": {
                                "id": f"qa-{sequence}", "session_id": params["id"], "sequence": sequence, "type": kind,
                                "timestamp": "2026-09-05T12:00:00.000000Z", "payload": {"text": text}}}}
                            connection.sendall((json.dumps(event) + "\n").encode())
        except (OSError, ValueError) as error:
            if not stop.is_set():
                state["gateway_error"] = str(error)

    worker = threading.Thread(target=gateway, daemon=True)
    worker.start()

    def pump(seconds=0.1):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], max(0, deadline - time.monotonic()))[0]:
                try:
                    part = os.read(terminal, 65536)
                    if not part:
                        return
                    captured.extend(part)
                except OSError as error:
                    if error.errno == errno.EIO:
                        return
                    raise

    def wait_for(predicate, label, timeout=20):
        deadline = time.monotonic() + timeout
        while not predicate():
            pump()
            assert time.monotonic() < deadline, f"{name}: timed out waiting for {label}"

    def calls(method):
        return [r for r in state["requests"] if r["method"] == method]

    def text():
        return ANSI.sub(b"", bytes(captured)).decode(errors="replace")

    def press(value):
        os.write(terminal, value)
        pump(0.2)

    try:
        # A freshly linked binary can take longer to launch on macOS. Keep the
        # interaction deadlines short, but give process startup its own budget.
        wait_for(lambda: "YOUR TASK" in text(), "fresh welcome screen", timeout=60)
        wait_for(lambda: "Understandthisproject" in "".join(text().split()), "first-run examples")
        if name == "starter":
            press(b"\x1bOQ")  # xterm F2
        else:
            press(b"Explain this project without changing files")
        assert not calls("interactive.start"), "typing or choosing an example must not start work"
        press(b"\r")
        wait_for(lambda: len(calls("account.login.start")) == 1, "sign-in request")
        wait_for(lambda: "QA-1234" in text(), "sign-in screen")
        if name == "cancel-retry":
            press(b"\x1b")
            wait_for(lambda: bool(calls("account.login.cancel")), "sign-in cancellation")
            state.update(connected=True, status="completed")
            pump(1.5)
            assert not calls("interactive.start"), "late authentication cannot revive a cancelled task"
            press(b"\r")
        elif name == "expired-retry":
            state.update(status="expired", error="Your sign-in code expired.")
            wait_for(lambda: "Retryconnection&start" in "".join(text().split()), "actionable expired-login screen")
            press(b"r")
            wait_for(lambda: len(calls("account.login.start")) == 2, "sign-in retry")
            state.update(connected=True, status="completed")
        else:
            state.update(connected=True, status="completed")
        if name == "start-refusal":
            wait_for(lambda: bool(state.get("refused")), "start refusal")
            wait_for(lambda: "selectedfolderisunavailable" in "".join(text().split()), "readable start error")
            press(b"\r")
        wait_for(lambda: len(calls("interactive.send_message")) == 1, "automatic first task")
        wait_for(lambda: "QAtaskcompleted" in "".join(text().split()), "first response in the terminal")
        pump(0.5)
        assert len(calls("interactive.start")) == (2 if name == "start-refusal" else 1)
        assert len(calls("interactive.send_message")) == 1
        submitted = calls("interactive.send_message")[0]["params"]["input"]
        assert submitted.startswith("Explore this project" if name == "starter" else "Explain this project")
        press(b"\x11")  # ctrl+q
        press(b"\r")
        wait_for(lambda: b"\x1b[?1049l" in captured, "terminal restoration")
        print(f"PASS {name}: fresh PTY → sign-in → one first task → response → clean exit", flush=True)
    finally:
        stop.set()
        listener.close()
        pump(0.1)
        try:
            ended, _ = os.waitpid(pid, os.WNOHANG)
            if not ended:
                os.kill(pid, signal.SIGTERM)
                os.waitpid(pid, 0)
        except ProcessLookupError:
            pass
        os.close(terminal)
        (directory / "terminal.ansi").write_bytes(captured)
        (directory / "requests.json").write_text(json.dumps(state["requests"], indent=2))
        token.unlink(missing_ok=True)


for scenario in ["starter", "cancel-retry", "expired-retry", "start-refusal"]:
    run_case(scenario)
