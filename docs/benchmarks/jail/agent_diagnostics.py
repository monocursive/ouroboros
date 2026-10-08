#!/usr/bin/env python3
"""Summarize OpenCode diagnostic timestamps without classifying model latency as Jail overhead."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re


def analyze(directory):
    result = json.loads((directory / 'result.json').read_text())
    rows = []
    for trial in result['rows']:
        path = directory / trial['name']
        logs = []
        for line in (path / 'stderr.txt').read_text(errors='replace').splitlines():
            match = re.search(r'timestamp=(\S+)', line)
            if match:
                logs.append((datetime.fromisoformat(match[1].replace('Z', '+00:00')).timestamp(), line))
        streams = [t for t,line in logs if 'message=stream ' in line and 'small=false' in line]
        disposal = [t for t,line in logs if 'message="disposing instance"' in line]
        output = []
        for line in (path / 'stdout.txt').read_text(errors='replace').splitlines():
            try: event = json.loads(line)
            except ValueError: continue
            if isinstance(event, dict) and isinstance(event.get('timestamp'), (int,float)):
                output.append((event['timestamp'] / 1000, event.get('type')))
        row = {'name': trial['name'], 'passed': trial['passed'], 'seconds': trial['seconds'],
               'main_stream_requests': len(streams),
               'rate_limit_log_entries': sum('Rate limit exceeded' in line for _,line in logs),
               'output_event_types': sorted({kind for _,kind in output if isinstance(kind,str)}),
               'model_stream_to_first_output_seconds': output[0][0] - streams[0] if output and streams else None,
               'last_output_to_disposal_seconds': disposal[-1] - output[-1][0] if output and disposal else None,
               'logged_startup_to_first_stream_seconds': streams[0] - logs[0][0] if streams and logs else None}
        if streams and row['rate_limit_log_entries'] and disposal:
            row['provider_refusal_through_disposal_seconds'] = disposal[-1] - streams[0]
        rows.append(row)
    return {'schema': 'ouro.jail.agent-diagnostics/1', 'matrix_status': result['status'], 'rows': rows,
            'interpretation': 'Timestamp intervals include agent/provider/tool work. They do not isolate causal sandbox overhead or prove the cause of earlier unlogged stalls.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.directory), indent=2))
