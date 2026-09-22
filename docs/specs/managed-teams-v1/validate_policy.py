# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0"]
# ///
"""Validate managed-policy document examples; this is not runtime enforcement."""

import copy
import json
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent
SAFE_INTEGER = 9_007_199_254_740_991


def read(name):
    return json.loads((ROOT / name).read_text())


def widening_paths(organization, project):
    """Normative subset oracle for the bounded, complete example documents."""
    errors = []
    if organization["scope"] != "organization" or project["scope"] != "project":
        errors.append("scope")
    if organization["organization_id"] != project["organization_id"]:
        errors.append("organization_id")
    for key in (
        "profiles", "launch_profiles", "data_classes", "worker_pools",
        "execution_regions", "model_processing_regions", "storage_regions",
    ):
        if not set(project[key]) <= set(organization[key]):
            errors.append(key)
    for service, capabilities in project["service_capabilities"].items():
        if service not in organization["service_capabilities"] or not set(capabilities) <= set(
            organization["service_capabilities"][service]
        ):
            errors.append(f"service_capabilities.{service}")
    for group in ("limits", "retention", "quotas"):
        for key, value in project[group].items():
            if value > organization[group][key]:
                errors.append(f"{group}.{key}")
    for group in ("capture", "artifacts"):
        for key, value in project[group].items():
            ceiling = organization[group][key]
            if isinstance(value, bool):
                wider = value and not ceiling
            elif isinstance(value, list):
                wider = not set(value) <= set(ceiling)
            else:
                wider = value > ceiling
            if wider:
                errors.append(f"{group}.{key}")
    for key, wider in (
        ("valid_from", lambda child, parent: child < parent),
        ("valid_until", lambda child, parent: child > parent),
    ):
        if wider(datetime.fromisoformat(project[key]), datetime.fromisoformat(organization[key])):
            errors.append(key)
    return sorted(errors)


def document_errors(validator, policy):
    errors = sorted(validator.iter_errors(policy), key=lambda error: str(error.path))
    if errors:
        return [".".join(map(str, error.path)) or "$" for error in errors]
    if datetime.fromisoformat(policy["valid_from"]) >= datetime.fromisoformat(policy["valid_until"]):
        return ["valid_until"]
    return []


def apply_changes(policy, changes):
    for change in changes:
        target = policy
        parts = change["path"].split(".")
        for part in parts[:-1]:
            target = target[part]
        target[parts[-1]] = change["value"]


def main():
    schema = read("policy.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    organization = read("organization-policy.json")
    project = read("project-policy.json")
    for policy in (organization, project):
        assert not document_errors(validator, policy), policy["policy_id"]
    assert not widening_paths(organization, project)
    cases = read("policy-cases.json")
    assert len({case["id"] for case in cases}) == len(cases)
    for case in cases:
        candidate = copy.deepcopy(project)
        ceiling = copy.deepcopy(organization)
        apply_changes(ceiling, case.get("organization_changes", []))
        assert not document_errors(validator, ceiling), case["id"]
        apply_changes(candidate, case["changes"])
        errors = document_errors(validator, candidate)
        actual = "invalid" if errors else "widening" if widening_paths(ceiling, candidate) else "valid"
        assert actual == case["expect"], (case["id"], actual, case["expect"])
        if actual == "widening":
            assert widening_paths(ceiling, candidate) == case["paths"], case["id"]
    assert schema["$defs"]["positive"]["maximum"] == SAFE_INTEGER
    print(f"Validated 1 managed-policy schema, 2 policy examples and {len(cases)} cases.")
    print("Document contracts only; identity, policy authorization and runtime containment are not tested.")


if __name__ == "__main__":
    main()
