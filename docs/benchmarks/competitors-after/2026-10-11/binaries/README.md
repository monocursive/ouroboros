# Exact tested Ouro executables

`vps` contains the Linux x86_64 executables; `pi` contains Linux ARM64 executables.
`ouro-jail-before` is the original benchmark build, and `ouro-jail` is the patched
build. All four hashes match the corresponding doctor reports and are listed in
[manifest.json](manifest.json). These are the exact binaries tested on the supplied
hosts, not newly issued release artifacts or a promise of other-host portability.

The paired harness needs both in a fresh run root's `bin` directory, alongside
the unchanged comparator/client installations. Follow [METHODS](../METHODS.md),
keep fresh output directories, and preserve strict observation and the original
policy. The source base, patch, build-source backup and Rust version are retained.
