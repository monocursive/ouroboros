import json, os, pathlib, socket, sys
assert sys.argv[1:] == ['space argument', 'a;$(false)', 'café']
assert os.uname().sysname == 'Linux'
assert not pathlib.Path('/Users/monocursive').exists()
try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(.2)
    s.connect(('1.1.1.1',443))
except OSError:
    blocked=True
else:
    blocked=False
assert blocked
pathlib.Path('result.json').write_text(json.dumps({'argv':sys.argv[1:], 'linux':True, 'network_blocked':blocked}))
print('FUNCTIONAL_OK', flush=True)
