# OpenShell gateway preparation, not a lifecycle score

`pilot-01/` failed configuration preflight before starting a gateway because
the harness omitted `--tls-client-ca`. `ready-02/` fixes that setup omission,
passes preflight, starts the owned native Docker gateway, registers its local
client certificate, and passes authenticated status with TLS verification.

The gateway remains available for the matching provider fixture. Neither record
claims that fixture has executed. Each directory includes the exact executed
harness and sanitized setup report. Vendor-generated private keys, signing
material, databases, client state and raw command logs stay outside Git.
