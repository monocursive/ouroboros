#!/usr/bin/env python3
"""Structural checks on the release workflow. Driven by scripts/check-release-workflow.sh.

Every check here answers a question that would otherwise be answered by pushing a tag.
None of them answer "does this work on a hosted runner" — see the honesty note at the
top of the workflow, and docs/DISTRIBUTION.md.
"""

import re
import sys

import yaml

# The one secret this workflow is allowed to reach for. A new name here should be a
# deliberate decision recorded in docs/DISTRIBUTION.md, not something that appears
# because an expression was copied.
ALLOWED_SECRETS = {"OURO_RELEASE_SIGNING_KEY"}

# Expression roots GitHub defines. Anything else is a typo that evaluates to empty and
# silently disables whatever it guards.
ALLOWED_CONTEXTS = {
    "github",
    "env",
    "vars",
    "job",
    "jobs",
    "steps",
    "runner",
    "secrets",
    "strategy",
    "matrix",
    "needs",
    "inputs",
    "always",
    "success",
    "failure",
    "cancelled",
    "hashFiles",
    "format",
    "join",
    "toJSON",
    "fromJSON",
    "contains",
    "startsWith",
    "endsWith",
}

EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
IDENTIFIER = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)")

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def walk_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from walk_strings(key)
            yield from walk_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_strings(item)


def main(path):
    raw = open(path, encoding="utf-8").read()

    check("\t" not in raw, "the file contains a tab; YAML indentation must be spaces")

    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        print(f"release.yml does not parse as YAML:\n{error}", file=sys.stderr)
        return 1

    check(isinstance(document, dict), "the top level is not a mapping")
    jobs = document.get("jobs") or {}
    check(isinstance(jobs, dict) and jobs, "there are no jobs")

    # --- names refer to things that exist -----------------------------------------

    for name, job in jobs.items():
        needs = job.get("needs")
        needs = [needs] if isinstance(needs, str) else (needs or [])

        for dependency in needs:
            check(
                dependency in jobs,
                f"job {name!r} needs {dependency!r}, which is not a job in this file",
            )

        for index, step in enumerate(job.get("steps") or []):
            check(
                "uses" in step or "run" in step,
                f"job {name!r} step {index} has neither `uses` nor `run`",
            )

    # --- every ${{ ... }} names a real context and a real matrix key ---------------

    for name, job in jobs.items():
        include = ((job.get("strategy") or {}).get("matrix") or {}).get("include") or []
        matrix_keys = set()
        for entry in include:
            matrix_keys |= set(entry)

        for text in walk_strings(job):
            for expression in EXPRESSION.findall(text):
                head = IDENTIFIER.search(expression)
                if not head:
                    continue

                root = head.group(1)
                check(
                    root in ALLOWED_CONTEXTS,
                    f"job {name!r} uses context {root!r}, which GitHub does not define",
                )

                for reference in re.findall(r"\bmatrix\.([A-Za-z0-9_-]+)", expression):
                    check(
                        reference in matrix_keys,
                        f"job {name!r} reads matrix.{reference}, which no matrix entry sets",
                    )

                for reference in re.findall(r"\bsecrets\.([A-Za-z0-9_-]+)", expression):
                    check(
                        reference in ALLOWED_SECRETS,
                        f"job {name!r} reads secrets.{reference}, which is not a documented "
                        f"secret for this workflow (allowed: {sorted(ALLOWED_SECRETS)})",
                    )

    # --- the signing pipeline is wired the way the docs say -----------------------

    publish = jobs.get("publish")
    check(publish is not None, "there is no `publish` job")

    if publish:
        steps = publish.get("steps") or []
        names = [step.get("name", "") for step in steps]
        uses = [step.get("uses", "") for step in steps]
        body = "\n".join(step.get("run", "") for step in steps)
        body_commands = "\n".join(
            line for line in body.splitlines() if not line.strip().startswith("#")
        )

        check(
            any(u.startswith("actions/checkout") for u in uses),
            "the publish job never checks out the tree, so dist/release.pub is not there "
            "to verify the signature against",
        )

        check(
            any("Sign SHA256SUMS" in n for n in names),
            "the publish job has no signing step",
        )

        # Order matters: the signature has to exist before the release is created.
        signing = next(i for i, n in enumerate(names) if "Sign SHA256SUMS" in n)
        publishing = next(
            (i for i, n in enumerate(names) if "Publish" in n), len(names)
        )
        check(
            signing < publishing,
            "the release is created before SHA256SUMS is signed",
        )

        check("minisign -S" in body_commands, "nothing signs SHA256SUMS")
        check(
            "minisign -V" in body_commands,
            "the workflow never verifies its own signature against the committed key, so a "
            "secret that does not match dist/release.pub would only be caught by a user",
        )
        check(
            "dist/release.pub" in body_commands,
            "the verification does not read the committed dist/release.pub",
        )
        check(
            "SHA256SUMS.minisig" in body_commands,
            "the signature file is never named",
        )

        # Fail-closed, in both directions.
        check(
            'if [[ -z "${OURO_RELEASE_SIGNING_KEY}" ]]' in body
            or "if [ -z \"${OURO_RELEASE_SIGNING_KEY}\" ]" in body,
            "a missing signing secret does not stop the release",
        )
        check(
            "unprovisioned placeholder" in body,
            "an unprovisioned dist/release.pub does not stop the release",
        )

        # And what the release does and does not carry.
        create = next(
            (step.get("run", "") for step in steps if "gh release create" in step.get("run", "")),
            "",
        )
        # Comments in the step body are prose about the commands, not commands. A check
        # that reads them fires on the sentence explaining why the thing is not done.
        commands = "\n".join(
            line for line in create.splitlines() if not line.strip().startswith("#")
        )

        check(create, "nothing creates a release")
        check(
            "dist/SHA256SUMS.minisig" in commands,
            "the signature is not uploaded with the release",
        )
        check(
            "dist/SHA256SUMS" in commands,
            "the checksum manifest is not uploaded with the release",
        )
        check(
            "dist/ouro-*" in commands,
            "the binaries are not uploaded with the release",
        )
        check(
            "dist/*" not in commands,
            "the release uploads dist/* — that would publish dist/release.pub beside the "
            "signature it checks, which is exactly the thing that proves nothing",
        )

    # --- the build job still names what it always named ---------------------------

    build = jobs.get("build")
    check(build is not None, "there is no `build` job")

    if build:
        include = ((build.get("strategy") or {}).get("matrix") or {}).get("include") or []
        triples = {entry.get("triple") for entry in include}
        check(
            triples
            == {
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
            },
            f"the build matrix triples {sorted(t for t in triples if t)} do not match the four "
            "in tui/src/update.rs TRIPLES and scripts/install.sh",
        )

    for failure in failures:
        print(f"  FAIL  {failure}")

    if failures:
        print(f"\n{checks - len(failures)} of {checks} checks passed")
        return 1

    print(f"release.yml: {checks} structural checks passed")
    print("UNPROVEN: no tag has run this workflow; nothing here executes a runner step.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
