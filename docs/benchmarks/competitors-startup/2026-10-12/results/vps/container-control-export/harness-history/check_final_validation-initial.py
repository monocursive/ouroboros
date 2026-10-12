#!/usr/bin/env python3
import json,re,sys
from pathlib import Path
root=Path(sys.argv[1]);host=sys.argv[2];allowed=json.loads((root/'harness/pi-known-validation-failures.json').read_text());rows=[]
for suite in ['review_linux','observer_linux','observer_j4_linux','observer_regression_linux','j4_loss_linux','j4_tracer_precision_linux','j4_closed_set_linux','j5_tracer_foreign_child_linux','j5_boundary_linux','j5_pseudofs_linux','security_alias_linux','j5_bwrap_resolution_linux']:
 s=(root/'results/validation'/(suite+'.log')).read_text();tail=s.split('failures:\n')[-1].split('test result:')[0]
 failures=[l.strip() for l in tail.splitlines() if re.fullmatch(r'    [A-Za-z0-9_]+',l)] if 'test result: FAILED' in s else []
 summaries=re.findall(r'test result:.*',s);assert summaries,(suite,'no test result; possible build failure')
 unexpected=set(failures)-set(allowed.get(suite,[]) if host=='pi' else [])
 rows.append({'suite':suite,'summary':summaries[-1],'failed_tests':failures,'unexpected_failed_tests':sorted(unexpected)})
 assert not unexpected,(suite,unexpected)
(root/'results/validation/assessment.json').write_text(json.dumps({'host':host,'suites':rows,'conformance_pass':host=='vps','pi_failures_retained_without_relaxing_tests':host=='pi','release_readiness_claim':False},indent=2)+'\n')
print('Final validation completed; original host/test limitations retained' if host=='pi' else 'All exercised final Linux integration suites pass')
