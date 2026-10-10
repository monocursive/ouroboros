#!/usr/bin/env python3
"""Verify recorded clean-VM onboarding and evidence-supported vendor learning."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib
from collections import Counter


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(directory, inputs, check):
    result = json.loads((directory / 'guest/result.json').read_bytes())
    vm = json.loads((directory / 'vm.json').read_bytes())
    build = result['build']['build']
    require(build['inputs'] == inputs and result['expected_inputs'] == inputs, 'stale build inputs')
    require(build['dirty'] is False and build['opt_level'] == '3' and not build['debug_assertions'], 'not a clean optimized build')
    require(build['revision'] == result['expected_revision'] == vm['revision'], 'revision disagreement')
    require(build['target'] == 'x86_64-unknown-linux-gnu', 'wrong VM target')
    require(result['vendor_version'] == '1.18.32', 'unexpected vendor version')
    if check == 'onboarding':
        require(vm['status'] == result['status'] == 'passed', 'VM did not pass')
        require(vm['fresh_overlay'] is True and not vm['host_policy_changes'], 'not a clean isolated VM')
        require(not any(result['rust_before'].values()) and not any(result['rust_after'].values()), 'Rust was installed in the guest')
        require(0 < result['workflow_seconds'] < 600 and result['main_workflow'] == 'passed', 'onboarding exceeded ten minutes or failed')
        require(result['distribution_checks'] == 'passed', 'signature/corruption tests did not pass')
        rows = {row['name']: row for row in result['rows']}
        for name in ['install', 'true', 'opencode', 'upgrade']:
            require(rows[name]['exit'] == 0, name + ' failed')
        for name in ['corrupt-archive', 'corrupt-signature']:
            require(rows[name]['exit'] != 0, name + ' was accepted')
        for name in ['true', 'opencode']:
            receipt = json.loads((directory / f'guest/{name}-jail.json').read_bytes())
            require(receipt['phase'] == 'settled' and receipt['containment'] == 'enforced'
                    and receipt['exec_observed'] is True and receipt['lifetime']['tree_empty'] is True
                    and receipt['lifetime']['integrity'] == 'verified' and receipt['outcome']['code'] == 0,
                    name + ' did not prove contained execution and settlement')
    elif check == 'learning':
        require(result.get('learning_workflow') == 'passed', 'real vendor learning did not pass')
        raw = (directory / 'guest/opencode-learn-jail.json').read_bytes()
        receipt = json.loads(raw)
        proposal = tomllib.loads((directory / 'guest/opencode-learned.toml').read_text())
        provenance = proposal['provenance']
        require(provenance['receipt_digest'] == 'sha256:' + hashlib.sha256(raw).hexdigest(), 'proposal is not bound to receipt bytes')
        require(provenance['attempt'] == receipt['attempt_id'], 'wrong learning attempt')
        require(provenance['build_inputs'] == inputs, 'wrong learning build inputs')
        require(provenance['revision'] == build['revision'], 'wrong learning revision')
        require(json.loads(provenance['coverage_json']) == receipt['coverage'], 'coverage was rewritten')
        require(set(receipt['coverage']) == {'exec', 'fs.deny', 'fs.write', 'limits', 'net', 'proxy.net'}, 'missing coverage classes')
        require(all(row['status'] == 'active' and not row['gaps'] for row in receipt['coverage'].values()), 'learning has incomplete coverage')
        events = [json.loads(line) for line in (directory / 'guest/opencode-learn-trace.ndjson').read_bytes().splitlines()]
        require(all(event['attempt_id'] == receipt['attempt_id'] for event in events), 'mixed attempt journal')
        require(dict(Counter(event['operation'] for event in events)) == provenance['event_counts'], 'event counts disagree')
        lookup = {f'{event["source"]}:{event["source_seq"]}': event for event in events}
        require(len(lookup) == len(events), 'duplicate event reference')
        fixture = result['learning_fixture']
        require(bool(proposal['read_only']) and str(Path(fixture).parent) not in proposal['read_only'], 'no supported subset, or parent widened')
        require(result['learning_fixture_proposed'] == (fixture in proposal['read_only']), 'fixture proposal status was rewritten')
        require(not set(proposal['read_only']) & set(proposal['unresolved_reads']), 'an unresolved read became a grant')
        for grant, kind in [(g, 'read') for g in proposal['read_only']] + [(g, 'network') for g in proposal['network_allow']]:
            references = provenance['evidence'].get(grant, [])
            require(bool(references), 'grant without evidence: ' + grant)
            for reference in references:
                event = lookup.get(reference)
                require(event is not None, 'invented event reference')
                fields = event['fields']
                if kind == 'read':
                    require(fields.get('kind') == 'learning_read' and fields.get('path') == grant
                            and fields.get('errno') in ['ENOENT', 'EACCES', 'EPERM'], 'read grant not justified by this exact denied read')
                else:
                    require(event['source'] == 'proxy' and event.get('decision') == 'deny'
                            and fields.get('reason') == 'host_not_allowed' and fields.get('destination') == grant,
                            'network grant not justified by a host denial')
        require(receipt['phase'] == 'settled' and receipt['lifetime']['tree_empty'] is True
                and receipt['outcome']['code'] == 0, 'vendor learning did not settle successfully')
    else:
        raise ValueError('unknown evidence check')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--check', choices=['onboarding', 'learning'], required=True)
    args = parser.parse_args()
    try:
        verify(args.directory, args.inputs, args.check)
    except (ValueError, KeyError, OSError) as error:
        parser.exit(1, f'preview evidence: {error}\n')
    print('PASS recorded Linux preview evidence:', args.check)


if __name__ == '__main__':
    main()
