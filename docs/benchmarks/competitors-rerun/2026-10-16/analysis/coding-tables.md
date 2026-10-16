# Rerun 2026-10-16 coding compatibility

| host | class | client | arm | attempted | passed | median success ms |
|---|---|---|---|---:|---:|---:|
| mac | native | claude | direct | 6 | 6 | 19044.7 |
| mac | native | claude | greywall | 6 | 0 | None |
| mac | native | claude | mxc | 6 | 6 | 23402.5 |
| mac | native | codex | direct | 6 | 6 | 15387.4 |
| mac | native | codex | greywall | 6 | 0 | None |
| mac | native | codex | mxc | 6 | 0 | None |
| mac | native | opencode | direct | 6 | 6 | 25969.5 |
| mac | native | opencode | greywall | 6 | 0 | None |
| mac | native | opencode | mxc | 6 | 6 | 25857.0 |
| pi | native | claude | direct | 6 | 6 | 23420.8 |
| pi | native | claude | greywall | 6 | 6 | 37426.7 |
| pi | native | claude | mxc | 6 | 6 | 24922.1 |
| pi | native | claude | ouro | 6 | 6 | 23831.1 |
| pi | native | codex | direct | 6 | 6 | 23572.1 |
| pi | native | codex | greywall | 6 | 6 | 64959.3 |
| pi | native | codex | mxc | 6 | 6 | 29457.4 |
| pi | native | codex | ouro | 6 | 6 | 19229.5 |
| pi | native | opencode | direct | 6 | 6 | 46658.9 |
| pi | native | opencode | greywall | 6 | 6 | 75383.1 |
| pi | native | opencode | mxc | 6 | 6 | 54384.6 |
| pi | native | opencode | ouro | 6 | 6 | 48358.3 |
| vps | native | claude | direct | 6 | 6 | 21462.8 |
| vps | native | claude | greywall | 6 | 6 | 34500.9 |
| vps | native | claude | mxc | 6 | 6 | 21401.9 |
| vps | native | claude | ouro | 6 | 6 | 23974.3 |
| vps | native | codex | direct | 6 | 6 | 14595.5 |
| vps | native | codex | greywall | 6 | 6 | 62914.9 |
| vps | native | codex | mxc | 6 | 6 | 24239.4 |
| vps | native | codex | ouro | 6 | 6 | 16036.6 |
| vps | native | opencode | direct | 6 | 6 | 27718.1 |
| vps | native | opencode | greywall | 6 | 6 | 49688.1 |
| vps | native | opencode | mxc | 6 | 6 | 31655.2 |
| vps | native | opencode | ouro | 6 | 6 | 29101.5 |
| mac | container | claude | docker | 6 | 6 | 21079.4 |
| mac | container | claude | openshell-ephemeral | 6 | 6 | 22027.4 |
| mac | container | claude | openshell-warm | 6 | 6 | 20510.0 |
| mac | container | codex | docker | 6 | 6 | 15754.8 |
| mac | container | codex | openshell-ephemeral | 6 | 6 | 18438.0 |
| mac | container | codex | openshell-warm | 6 | 6 | 16138.6 |
| mac | container | opencode | docker | 6 | 6 | 26430.2 |
| mac | container | opencode | openshell-ephemeral | 6 | 6 | 26742.7 |
| mac | container | opencode | openshell-warm | 6 | 6 | 27846.2 |
| pi | container | claude | docker | 6 | 6 | 25975.1 |
| pi | container | codex | docker | 6 | 6 | 33529.1 |
| pi | container | opencode | docker | 6 | 6 | 74587.7 |
| vps | container | claude | docker | 6 | 6 | 20271.9 |
| vps | container | claude | openshell-ephemeral | 6 | 6 | 19872.7 |
| vps | container | claude | openshell-warm | 6 | 6 | 19873.8 |
| vps | container | codex | docker | 6 | 6 | 17611.5 |
| vps | container | codex | openshell-ephemeral | 6 | 6 | 18685.9 |
| vps | container | codex | openshell-warm | 6 | 6 | 16311.3 |
| vps | container | opencode | docker | 6 | 6 | 28360.5 |
| vps | container | opencode | openshell-ephemeral | 6 | 6 | 28768.0 |
| vps | container | opencode | openshell-warm | 6 | 6 | 30679.4 |


# Workflow (inventory CLI), one run per client/arm

| host | class | client | arm | success | exit |
|---|---|---|---|---|---:|
| mac | container | claude | docker | True | 0 |
| mac | container | claude | openshell-ephemeral | True | 0 |
| mac | container | claude | openshell-warm | True | 0 |
| mac | container | codex | docker | True | 0 |
| mac | container | codex | openshell-ephemeral | True | 0 |
| mac | container | codex | openshell-warm | True | 0 |
| mac | container | opencode | docker | True | 0 |
| mac | container | opencode | openshell-ephemeral | True | 0 |
| mac | container | opencode | openshell-warm | True | 0 |
| mac | native | claude | direct | True | 0 |
| mac | native | claude | greywall | False | 65 |
| mac | native | claude | mxc | True | 0 |
| mac | native | codex | direct | True | 0 |
| mac | native | codex | greywall | False | 65 |
| mac | native | codex | mxc | False | 1 |
| mac | native | opencode | direct | True | 0 |
| mac | native | opencode | greywall | False | 65 |
| mac | native | opencode | mxc | True | 0 |
| pi | container | claude | docker | True | 0 |
| pi | container | codex | docker | True | 0 |
| pi | container | opencode | docker | True | 0 |
| pi | native | claude | direct | True | 0 |
| pi | native | claude | greywall | True | 0 |
| pi | native | claude | mxc | True | 0 |
| pi | native | claude | ouro | True | 0 |
| pi | native | codex | direct | True | 0 |
| pi | native | codex | greywall | True | 0 |
| pi | native | codex | mxc | True | 0 |
| pi | native | codex | ouro | True | 0 |
| pi | native | opencode | direct | True | 0 |
| pi | native | opencode | greywall | True | 0 |
| pi | native | opencode | mxc | True | 0 |
| pi | native | opencode | ouro | True | 0 |
| vps | container | claude | docker | True | 0 |
| vps | container | claude | openshell-ephemeral | True | 0 |
| vps | container | claude | openshell-warm | True | 0 |
| vps | container | codex | docker | True | 0 |
| vps | container | codex | openshell-ephemeral | True | 0 |
| vps | container | codex | openshell-warm | True | 0 |
| vps | container | opencode | docker | True | 0 |
| vps | container | opencode | openshell-ephemeral | True | 0 |
| vps | container | opencode | openshell-warm | True | 0 |
| vps | native | claude | direct | True | 0 |
| vps | native | claude | greywall | True | 0 |
| vps | native | claude | mxc | False | 1 |
| vps | native | claude | ouro | True | 0 |
| vps | native | codex | direct | True | 0 |
| vps | native | codex | greywall | True | 0 |
| vps | native | codex | mxc | True | 0 |
| vps | native | codex | ouro | True | 0 |
| vps | native | opencode | direct | True | 0 |
| vps | native | opencode | greywall | True | 0 |
| vps | native | opencode | mxc | True | 0 |
| vps | native | opencode | ouro | True | 0 |
