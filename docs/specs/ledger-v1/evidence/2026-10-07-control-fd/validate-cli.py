# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""Check saved real control CLI responses against the current wire contracts."""
import importlib.util
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ledger_contract", root / "validate_contract.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)
validators = contract.jail.build_validators(
    contract.jail.load_schemas(contract.JAIL) | contract.jail.load_schemas(root)
)
for name in sys.argv[1:]:
    directory = Path(name)
    validators["run"].validate(json.loads((directory / "control-cli.json").read_text()))
    for line in (directory / "events-cli.ndjson").read_bytes().splitlines():
        record = json.loads(line)
        validators["record"].validate(record)
        assert contract.rfc8785.dumps(record) == line
    print(f"{directory.name}: actual control run response and canonical events conform")
