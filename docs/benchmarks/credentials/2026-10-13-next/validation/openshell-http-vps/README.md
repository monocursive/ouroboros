# OpenShell extension of the common HTTP lifecycle fixture

`completed-04/` contains the completed ten-case desired contract. Its Python
actor and HTTP/SSE resource handler match the completed Pi cohort byte for byte.
It runs on VPS with a non-root Ubuntu image and Python 3.12.3, rather than Pi
Python 3.13. Treat it as feature evidence, not a same-host performance comparison.

`image-01/` records the derived client image, which installs curl required by
the unchanged actor. Only the actor is uploaded into `/work`; private gateway
HOME, PKI, provider material and raw operator responses stay outside Git.

Preserved earlier attempts:

- `pilot-01/`: CLI rejects upload combined with a command, before sandbox launch.
- `pilot-02/`: policy rejects the symbolic Ubuntu identity, before sandbox launch.
- `pilot-03/`: real requests and update complete, but attached-provider deletion
  is refused. The later complete fixture uses supported provider detach.

Eight desired checks pass. The two remaining contract differences are authorized
ancestor admission and immutable existing static credential references. Raw
`supported` flags reflect the controller's initial operator-availability
assumption, not proof of narrower capability semantics. See
`../../analysis/matched-openshell-http.json` and the parent benchmark README.

Stream closure takes 9.490 seconds from detach initiation and occurs during the
operator's wait. The observation contract includes closure during the operation
and ends three seconds after completion; it does not certify a three-second
end-to-end revocation latency. The same application survives until the 70-second
late request, then finishes normally. This static-provider fixture is not a
test of native OAuth refresh or the separate refresh-managed stable handles.
