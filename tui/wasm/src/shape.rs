//! The structural bound in front of the compiler: what a component may *be* before wasmtime is
//! asked to compile it.
//!
//! # Why bytes are not a bound
//!
//! [`crate::host::MAX_COMPONENT_BYTES`] caps what is read off disk, and for a long time that was
//! the only thing standing between a peer and the JIT. It is not a bound on work. Cranelift
//! compiles every function a component's core modules declare, whether or not anything reaches
//! them, and its cost is superlinear in the two things a component chooses freely: how many
//! functions there are and how many bytes of code they hold. Measured on the release helper
//! (aarch64-apple-darwin, wasmtime 48.0.1, one thread — `parallel-compilation` is deliberately
//! absent), against components of *n* functions of 40 arithmetic instructions each:
//!
//! | functions | code | `Component::new` |
//! |---|---|---|
//! | 5 000 | 2 MiB | 0.44 s |
//! | 10 000 | 4 MiB | 0.92 s |
//! | 20 000 | 8 MiB | 2.23 s |
//! | 30 000 | 12 MiB | 4.36 s |
//! | 145 000 | 61 MiB | 28.9 s |
//!
//! Every one of those is a *valid component in this world*: it exports `describe`, `init` and
//! `handle-message`, imports only `log`, and passes [`crate::world::check`]. The helper is
//! sequential, so a single `load` of the last one stops every hook and every capability on the
//! node for half a minute, and the daemon's 30-second `load` deadline then breaks the pool and
//! drops every live instance with it. Nothing about fuel, the epoch deadline or the memory
//! ceiling touches this: all three are bounds on a *running guest*, and none of them is armed
//! yet — there is no store.
//!
//! # What this module bounds, and why a watchdog would not do
//!
//! A wall-clock watchdog around `Component::new` cannot help, because cranelift cannot be
//! interrupted: the thread would still burn the CPU to the end, and the helper would still be
//! sequential behind it. The only bound that costs nothing is one taken *before* the compiler
//! runs, on the shape of the input. [`check`] walks the component and every module and component
//! nested in it with `wasmparser` — the same parser wasmtime itself uses, already in this
//! binary's graph — reading section headers and counts without decoding a single instruction,
//! and refuses [`crate::refusal::COMPONENT_TOO_COMPLEX`] the moment any of these is exceeded:
//!
//! * **[`MAX_CODE_BYTES`] and [`MAX_FUNCTIONS`]** — the two dimensions the table above measures,
//!   summed across every core module in the tree. At both bounds at once, which is the worst
//!   case this helper will admit, `Component::new` takes **1.19 s** on the release build.
//! * **[`MAX_TYPES`], [`MAX_IMPORTS`], [`MAX_EXPORTS`], [`MAX_DEFINITIONS`]** — counts, summed
//!   the same way. Type and index spaces are cheap per entry and ruinous in bulk.
//! * **[`MAX_SEGMENT_BYTES`]** — data and element segment bytes, which are copied rather than
//!   compiled but are still copied.
//! * **[`MAX_DEPTH`], [`MAX_CORE_MODULES`], [`MAX_NESTED_COMPONENTS`]** — how deeply and how
//!   widely a component may nest. The walk itself is iterative and cannot be made to recurse,
//!   but wasmtime's translation of a five-thousand-deep nest is not this process's problem to
//!   have.
//! * **[`MAX_SECTIONS`]** — a bound on *this pass*, so a component of a million empty sections
//!   cannot make the cheap check expensive.
//!
//! The numbers are picked from measurement, not from taste: they keep the worst admissible
//! component near a second, and they leave a real guest room it will never need. The lane's
//! acceptance guest — `test/support/wasm/echo.wasm`, a `wasm32-wasip2` Rust component built by
//! `make wasm-guest`, 48 333 bytes — walks to:
//!
//! | | it declares | the bound | headroom |
//! |---|---|---|---|
//! | functions | 101 | 20 000 | 198× |
//! | code bytes | 40 721 | 4 194 304 | 103× |
//! | types | 27 | 8 192 | 303× |
//! | segment bytes | 6 049 | 4 194 304 | 693× |
//! | definitions | 27 | 16 384 | 607× |
//! | imports / exports | 4 / 14 | 1 024 | 256× / 73× |
//! | core modules | 3 | 64 | 21× |
//! | sections | 46 | 8 192 | 178× |
//! | nesting | 1 | 8 | 8× |
//!
//! Two orders of magnitude on the tightest dimension, so a capability an order of magnitude
//! larger than the reference guest is still nowhere near a refusal. `doctor` reports every one
//! of these, so an owner can read the ceiling rather than discover it.
//!
//! # The residual, stated
//!
//! This is a bound on *admission*, not a proof about compile time. Cranelift's cost is not a
//! function of these counts alone — a single function of pathological control flow can cost more
//! than its bytes suggest, and a future wasmtime may cost differently — so the honest claim is
//! narrow: **the worst case this helper will hand to `Component::new` is bounded, measured, and
//! about a second**, and anything past the bound is refused without the compiler ever seeing it.
//!
//! Two things are counted but not weighed. A custom section — the name section, a producers
//! section — counts toward [`MAX_SECTIONS`] like any other, but its *bytes* are bounded only by
//! [`crate::host::MAX_COMPONENT_BYTES`]: wasmtime skips them, so a component that is sixty
//! mebibytes of custom section is a component that is mostly ignored, and the cost of admitting
//! it is the read and the digest rather than the compile. The same goes for whatever section a
//! future wasmparser learns to emit that this walk does not name: it falls through to
//! [`MAX_SECTIONS`] and nothing finer. That is the direction to fail in — a new section kind is
//! counted, not silently exempt — but it is a bound on *how many*, not on how large.

use wasmparser::{Parser, Payload};

use crate::refusal::{self, Refusal};

/// Core code-section bytes, summed across every core module in the component tree. Four
/// mebibytes: see the table in the module header — at this bound *and* [`MAX_FUNCTIONS`] at once
/// the release helper compiles in 1.19 s, and the reference guest's whole binary is 48 KiB.
pub const MAX_CODE_BYTES: usize = 4 * 1024 * 1024;

/// Core functions, summed across every core module. Cranelift's per-function overhead is the
/// other half of the cost: 20 000 functions of one instruction each is 0.73 s on their own.
pub const MAX_FUNCTIONS: u32 = 20_000;

/// Type-space entries — core types, component types, and core types declared in a component —
/// summed across the tree.
pub const MAX_TYPES: u32 = 8_192;

/// Declared imports, core and component, summed across the tree. This world declares one.
pub const MAX_IMPORTS: u32 = 1_024;

/// Declared exports, core and component, summed across the tree. This world declares three.
pub const MAX_EXPORTS: u32 = 1_024;

/// Everything else with an index space and a count: tables, memories, globals, tags, element
/// segments, core and component instances, aliases and canonical built-ins. A catch-all, so a
/// bomb made of ten million globals is refused by *something* rather than by nothing.
pub const MAX_DEFINITIONS: u32 = 16_384;

/// Data and element segment bytes, summed across the tree. Segments are copied rather than
/// compiled, so they are cheaper per byte than code — but not free, and not unbounded. Four
/// mebibytes is eighty-odd times the reference guest's whole binary.
pub const MAX_SEGMENT_BYTES: usize = 4 * 1024 * 1024;

/// How deeply components and core modules may nest *below the outermost component*, which is
/// level zero. The reference guest reaches level one: a component holding core modules.
pub const MAX_DEPTH: u32 = 8;

/// How many core modules the tree may hold in total.
pub const MAX_CORE_MODULES: u32 = 64;

/// How many nested components the tree may hold in total.
pub const MAX_NESTED_COMPONENTS: u32 = 64;

/// How many sections this pass will walk before giving up. A bound on the *checker*: without it,
/// a component of a million one-byte sections makes the cheap pre-pass the expensive part.
pub const MAX_SECTIONS: u32 = 8_192;

/// What the walk counted. Every field is a total over the component and everything nested in it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Census {
    pub sections: u32,
    pub depth: u32,
    pub core_modules: u32,
    pub nested_components: u32,
    pub functions: u32,
    pub code_bytes: usize,
    pub segment_bytes: usize,
    pub types: u32,
    pub imports: u32,
    pub exports: u32,
    pub definitions: u32,
}

fn too_complex(what: &str, got: impl std::fmt::Display, cap: impl std::fmt::Display) -> Refusal {
    refusal::refuse(
        refusal::COMPONENT_TOO_COMPLEX,
        format!(
            "component declares {got} {what}, and this helper compiles at most {cap}; \
             it was refused before wasmtime was asked to compile it"
        ),
    )
}

/// Walks these bytes and refuses them if they are shaped to be expensive to compile.
///
/// A parse failure is deliberately **not** a refusal here. These bytes are about to be handed to
/// wasmtime, which validates them with this same parser and says far more useful things about
/// what is wrong with them; a component this walk cannot follow is one `Component::new` will
/// reject, and it should reject it in its own words. So the walk stops and the compiler speaks.
pub fn check(bytes: &[u8]) -> Result<Census, Refusal> {
    let mut census = Census::default();
    let mut depth = 0u32;

    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(payload) = payload else {
            return Ok(census);
        };

        // A function body is not a section, and neither is the header or the closing brace of a
        // module: bounding bodies is [`MAX_FUNCTIONS`]'s job, done at the section header before
        // a single body is walked, and bounding modules is [`MAX_CORE_MODULES`]'s. Counting
        // those here too would make this bound mean a number nobody could work out.
        if !matches!(
            payload,
            Payload::CodeSectionEntry(_) | Payload::Version { .. } | Payload::End(_)
        ) {
            census.sections = census.sections.saturating_add(1);
            if census.sections > MAX_SECTIONS {
                return Err(too_complex("sections", census.sections, MAX_SECTIONS));
            }
        }

        match payload {
            Payload::ModuleSection { .. } => {
                census.core_modules = census.core_modules.saturating_add(1);
                if census.core_modules > MAX_CORE_MODULES {
                    return Err(too_complex(
                        "core modules",
                        census.core_modules,
                        MAX_CORE_MODULES,
                    ));
                }
                depth = depth.saturating_add(1);
                census.depth = census.depth.max(depth);
                if depth > MAX_DEPTH {
                    return Err(too_complex("levels of nesting", depth, MAX_DEPTH));
                }
            }
            Payload::ComponentSection { .. } => {
                census.nested_components = census.nested_components.saturating_add(1);
                if census.nested_components > MAX_NESTED_COMPONENTS {
                    return Err(too_complex(
                        "nested components",
                        census.nested_components,
                        MAX_NESTED_COMPONENTS,
                    ));
                }
                depth = depth.saturating_add(1);
                census.depth = census.depth.max(depth);
                if depth > MAX_DEPTH {
                    return Err(too_complex("levels of nesting", depth, MAX_DEPTH));
                }
            }
            Payload::End(_) => depth = depth.saturating_sub(1),

            Payload::CodeSectionStart { count, size, .. } => {
                census.functions = census.functions.saturating_add(count);
                if census.functions > MAX_FUNCTIONS {
                    return Err(too_complex("functions", census.functions, MAX_FUNCTIONS));
                }
                census.code_bytes = census.code_bytes.saturating_add(size as usize);
                if census.code_bytes > MAX_CODE_BYTES {
                    return Err(too_complex(
                        "bytes of code",
                        census.code_bytes,
                        MAX_CODE_BYTES,
                    ));
                }
            }
            // Counted at the section header above; walking the outlined bodies costs nothing and
            // says nothing this pass needs.
            Payload::CodeSectionEntry(_) => {}

            Payload::TypeSection(reader) => census.types = add(census.types, reader.count()),
            Payload::CoreTypeSection(reader) => census.types = add(census.types, reader.count()),
            Payload::ComponentTypeSection(reader) => {
                census.types = add(census.types, reader.count())
            }

            Payload::ImportSection(reader) => census.imports = add(census.imports, reader.count()),
            Payload::ComponentImportSection(reader) => {
                census.imports = add(census.imports, reader.count())
            }

            Payload::ExportSection(reader) => census.exports = add(census.exports, reader.count()),
            Payload::ComponentExportSection(reader) => {
                census.exports = add(census.exports, reader.count())
            }

            Payload::DataSection(reader) => {
                census.segment_bytes = census
                    .segment_bytes
                    .saturating_add(reader.range().end - reader.range().start);
            }
            Payload::ElementSection(reader) => {
                census.segment_bytes = census
                    .segment_bytes
                    .saturating_add(reader.range().end - reader.range().start);
                census.definitions = add(census.definitions, reader.count());
            }

            Payload::TableSection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }
            Payload::MemorySection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }
            Payload::GlobalSection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }
            Payload::TagSection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }
            Payload::InstanceSection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }
            Payload::ComponentInstanceSection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }
            Payload::ComponentAliasSection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }
            Payload::ComponentCanonicalSection(reader) => {
                census.definitions = add(census.definitions, reader.count())
            }

            _ => {}
        }

        if census.types > MAX_TYPES {
            return Err(too_complex("types", census.types, MAX_TYPES));
        }
        if census.imports > MAX_IMPORTS {
            return Err(too_complex("imports", census.imports, MAX_IMPORTS));
        }
        if census.exports > MAX_EXPORTS {
            return Err(too_complex("exports", census.exports, MAX_EXPORTS));
        }
        if census.definitions > MAX_DEFINITIONS {
            return Err(too_complex(
                "tables, memories, globals, segments, instances and aliases",
                census.definitions,
                MAX_DEFINITIONS,
            ));
        }
        if census.segment_bytes > MAX_SEGMENT_BYTES {
            return Err(too_complex(
                "bytes of data and element segments",
                census.segment_bytes,
                MAX_SEGMENT_BYTES,
            ));
        }
    }

    Ok(census)
}

fn add(total: u32, count: u32) -> u32 {
    total.saturating_add(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty component is in every bound, and its census is all zeroes but for the section
    /// the version header is counted as.
    #[test]
    fn the_empty_component_is_admitted() {
        let bytes = wat::parse_str("(component)").expect("the empty component assembles");
        let census = check(&bytes).expect("nothing about an empty component is expensive");
        assert_eq!(census.functions, 0);
        assert_eq!(census.code_bytes, 0);
        assert_eq!(census.core_modules, 0);
    }

    /// Bytes that are not a component at all are not this pass's to refuse: `Component::new`
    /// says what is wrong with them, in words about wasm rather than words about counts.
    #[test]
    fn unparseable_bytes_are_left_to_the_compiler() {
        assert!(check(b"not wasm at all").is_ok());
        assert!(check(&[]).is_ok());
        // A truncated but plausibly-framed component: the walk stops, it does not refuse.
        let bytes = wat::parse_str("(component)").expect("assembles");
        assert!(check(&bytes[..bytes.len() - 1]).is_ok());
    }

    /// Depth is counted, and a nest past the bound is refused without the walk recursing.
    #[test]
    fn nesting_past_the_bound_is_refused() {
        let deep = format!(
            "{}{}",
            "(component ".repeat(MAX_DEPTH as usize + 2),
            ")".repeat(MAX_DEPTH as usize + 2)
        );
        let bytes = wat::parse_str(&deep).expect("a deep nest assembles");
        let refusal = check(&bytes).expect_err("a nest past the bound is refused");
        assert_eq!(refusal.refusal, "component_too_complex");
        assert!(
            refusal.message.contains("nesting"),
            "the refusal must name the bound: {}",
            refusal.message
        );

        // Exactly at the bound is admitted: the outermost component is level zero, so
        // `MAX_DEPTH + 1` opening components reach level `MAX_DEPTH` and no further.
        let at = format!(
            "{}{}",
            "(component ".repeat(MAX_DEPTH as usize + 1),
            ")".repeat(MAX_DEPTH as usize + 1)
        );
        let bytes = wat::parse_str(&at).expect("assembles");
        assert!(check(&bytes).is_ok(), "the bound itself must be reachable");
    }

    /// A core module holding `n` distinct function types, wrapped in a component.
    ///
    /// Distinct by construction: the parameter list is `n` written in base four over the four
    /// numeric types, so seven parameters are enough for every index this test reaches and the
    /// text stays linear rather than quadratic in `n`.
    fn with_types(n: u32) -> Vec<u8> {
        const DIGITS: [&str; 4] = ["i32", "i64", "f32", "f64"];
        let mut inner = String::new();
        for index in 0..n {
            inner.push_str("(type (func (param");
            let mut rest = index;
            for _ in 0..7 {
                inner.push(' ');
                inner.push_str(DIGITS[(rest % 4) as usize]);
                rest /= 4;
            }
            inner.push_str(")))\n");
        }
        assemble(&format!("(component (core module {inner}))"))
    }

    fn with_imports(n: u32) -> Vec<u8> {
        let inner: String = (0..n)
            .map(|index| format!("(import \"m\" \"f{index}\" (func))\n"))
            .collect();
        assemble(&format!("(component (core module {inner}))"))
    }

    fn with_exports(n: u32) -> Vec<u8> {
        let inner: String = (0..n)
            .map(|index| format!("(func (export \"e{index}\"))\n"))
            .collect();
        assemble(&format!("(component (core module {inner}))"))
    }

    fn with_globals(n: u32) -> Vec<u8> {
        let inner: String = (0..n).map(|_| "(global i32 (i32.const 0))\n").collect();
        assemble(&format!("(component (core module {inner}))"))
    }

    fn with_data(bytes: usize) -> Vec<u8> {
        let payload = "a".repeat(bytes);
        assemble(&format!(
            "(component (core module (memory 1000) (data (i32.const 0) \"{payload}\")))"
        ))
    }

    fn assemble(text: &str) -> Vec<u8> {
        wat::parse_str(text).unwrap_or_else(|error| panic!("the probe assembles: {error}"))
    }

    /// Every count bound, from both sides: exactly at it is admitted, one past it is refused by
    /// name. A bound nothing can reach is as much a bug as a bound nothing enforces, so both
    /// halves are asserted for each.
    ///
    /// The byte-shaped bounds — [`MAX_CODE_BYTES`], [`MAX_FUNCTIONS`] — are proved against the
    /// real binary in `tests/containment.rs`, where the timing that justifies their numbers can
    /// be observed too.
    #[test]
    fn every_count_bound_is_reachable_and_refuses_past_itself() {
        let cases: [(&str, Vec<u8>, Vec<u8>); 5] = [
            ("types", with_types(MAX_TYPES), with_types(MAX_TYPES + 1)),
            (
                "imports",
                with_imports(MAX_IMPORTS),
                with_imports(MAX_IMPORTS + 1),
            ),
            (
                "exports",
                with_exports(MAX_EXPORTS),
                with_exports(MAX_EXPORTS + 1),
            ),
            (
                "tables, memories, globals",
                with_globals(MAX_DEFINITIONS),
                with_globals(MAX_DEFINITIONS + 1),
            ),
            (
                "bytes of data and element segments",
                with_data(MAX_SEGMENT_BYTES - 4096),
                with_data(MAX_SEGMENT_BYTES + 4096),
            ),
        ];

        for (what, at, over) in cases {
            check(&at).unwrap_or_else(|refusal| {
                panic!("the {what} bound must be reachable: {}", refusal.message)
            });

            let refusal = check(&over)
                .err()
                .unwrap_or_else(|| panic!("{what} past the bound must be refused"));
            assert_eq!(refusal.refusal, "component_too_complex");
            assert!(
                refusal.message.contains(what),
                "the refusal must name the {what} bound: {}",
                refusal.message
            );
        }
    }

    /// The bound on the *checker*. A component of nothing but empty custom sections costs
    /// wasmtime nothing and costs this walk one iteration each, so the walk gives up too.
    ///
    /// Hand-assembled, because "an empty custom section" is not a thing the text format will
    /// write: a component preamble, then `MAX_SECTIONS + 1` sections of id 0 holding a
    /// zero-length name and nothing else.
    #[test]
    fn a_component_of_nothing_but_sections_is_refused() {
        let preamble = wat::parse_str("(component)").expect("assembles");
        let mut bytes = preamble[..8].to_vec();
        for _ in 0..MAX_SECTIONS + 1 {
            bytes.extend_from_slice(&[0x00, 0x01, 0x00]);
        }

        let refusal = check(&bytes).expect_err("a million sections is a refusal");
        assert_eq!(refusal.refusal, "component_too_complex");
        assert!(refusal.message.contains("sections"), "{}", refusal.message);

        // Exactly the bound is walked without complaint, so it is reachable rather than a trap.
        let mut bytes = preamble[..8].to_vec();
        for _ in 0..MAX_SECTIONS {
            bytes.extend_from_slice(&[0x00, 0x01, 0x00]);
        }
        let census = check(&bytes).expect("the bound itself must be reachable");
        assert_eq!(census.sections, MAX_SECTIONS);
    }

    /// The bounds are the numbers that were measured, and this is what says so.
    ///
    /// Every other test here builds its fixtures *from* these constants, which makes them
    /// excellent at proving the bound is enforced and reachable and completely blind to the
    /// bound being moved: raise `MAX_TYPES` to a million and a test that generates
    /// `MAX_TYPES + 1` types goes on passing while the ceiling it was defending is gone. So the
    /// numbers are pinned. Changing one should be a deliberate act with a fresh measurement
    /// behind it — the table in this module's header — and failing this assertion is what makes
    /// it deliberate.
    #[test]
    fn the_bounds_are_the_measured_ones() {
        assert_eq!(MAX_CODE_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_FUNCTIONS, 20_000);
        assert_eq!(MAX_TYPES, 8_192);
        assert_eq!(MAX_IMPORTS, 1_024);
        assert_eq!(MAX_EXPORTS, 1_024);
        assert_eq!(MAX_DEFINITIONS, 16_384);
        assert_eq!(MAX_SEGMENT_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_DEPTH, 8);
        assert_eq!(MAX_CORE_MODULES, 64);
        assert_eq!(MAX_NESTED_COMPONENTS, 64);
        assert_eq!(MAX_SECTIONS, 8_192);
    }

    /// Every bound names itself, so an owner reading a refusal learns which one it hit.
    #[test]
    fn a_refusal_names_the_bound_and_the_ceiling() {
        let refusal = too_complex("functions", 999_999, MAX_FUNCTIONS);
        assert_eq!(refusal.refusal, "component_too_complex");
        assert!(refusal.message.contains("999999"));
        assert!(refusal.message.contains(&MAX_FUNCTIONS.to_string()));
    }
}
