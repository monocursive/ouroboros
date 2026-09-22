//! A small classic-BPF (cBPF) assembler for seccomp filters.
//!
//! The kernel takes a seccomp filter as an array of `struct sock_filter`, in
//! which every jump target is a *relative* offset stored in a single byte.
//! Writing those offsets by hand is how filters acquire silent holes, so this
//! module keeps the filter symbolic until the last moment: instructions carry
//! label names, [`Asm::assemble`] resolves them, and an offset that will not
//! fit in a byte is an error rather than a wrap-around.
//!
//! The module is pure data. It describes the Linux ABI but performs no
//! syscalls, so it compiles and its tests run on every host; only
//! [`Program::sock_fprog`] is Linux-only.

use std::collections::HashMap;
use std::fmt;

use sha2::{Digest, Sha256};

/// Maximum number of instructions the kernel accepts in one filter
/// (`BPF_MAXINSNS`).
pub const MAX_INSNS: usize = 4096;

// Instruction classes and modifiers, from `linux/bpf_common.h`.
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// Load a 32-bit word from an absolute offset in the seccomp data block.
pub const CODE_LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
/// Jump if the accumulator equals the immediate.
pub const CODE_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
/// Jump if the accumulator has any bit of the immediate set.
pub const CODE_JSET_K: u16 = BPF_JMP | BPF_JSET | BPF_K;
/// Unconditional jump; the distance lives in `k`, not in a byte.
pub const CODE_JA: u16 = BPF_JMP | BPF_JA | BPF_K;
/// Return the immediate as the filter's verdict.
pub const CODE_RET_K: u16 = BPF_RET | BPF_K;

/// One classic-BPF instruction, laid out exactly as `struct sock_filter`.
///
/// `#[repr(C)]` is load-bearing: a slice of these is handed to the kernel as
/// the filter program, and [`Program::to_bytes`] serialises the same layout
/// for the digest.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SockFilter {
    /// Opcode.
    pub code: u16,
    /// Relative offset taken when the comparison is true.
    pub jt: u8,
    /// Relative offset taken when the comparison is false.
    pub jf: u8,
    /// Immediate operand.
    pub k: u32,
}

impl SockFilter {
    /// Serialise one instruction the way the kernel sees it in memory on a
    /// little-endian host (x86_64 and aarch64, the two architectures this
    /// project targets).
    #[must_use]
    pub fn to_bytes(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0..2].copy_from_slice(&self.code.to_le_bytes());
        out[2] = self.jt;
        out[3] = self.jf;
        out[4..8].copy_from_slice(&self.k.to_le_bytes());
        out
    }
}

/// Why a symbolic program could not be turned into instructions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BpfError {
    /// A jump named a label that the program never defines.
    UnknownLabel(String),
    /// The same label was defined twice.
    DuplicateLabel(String),
    /// A conditional jump's distance does not fit in the byte the ABI gives
    /// it. Use an unconditional `ja`, which carries a 32-bit distance.
    JumpTooFar {
        /// Index of the jumping instruction.
        from: usize,
        /// Index of the target instruction.
        to: usize,
    },
    /// A jump pointed backwards; classic BPF has no backward jumps.
    BackwardJump {
        /// Index of the jumping instruction.
        from: usize,
        /// Index of the target instruction.
        to: usize,
    },
    /// More instructions than `BPF_MAXINSNS`.
    TooManyInstructions(usize),
}

impl fmt::Display for BpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownLabel(l) => write!(f, "jump to undefined label `{l}`"),
            Self::DuplicateLabel(l) => write!(f, "label `{l}` defined twice"),
            Self::JumpTooFar { from, to } => {
                write!(f, "jump from {from} to {to} does not fit in one byte")
            }
            Self::BackwardJump { from, to } => {
                write!(f, "backward jump from {from} to {to} is not representable")
            }
            Self::TooManyInstructions(n) => {
                write!(
                    f,
                    "{n} instructions exceeds the kernel limit of {MAX_INSNS}"
                )
            }
        }
    }
}

impl std::error::Error for BpfError {}

#[derive(Clone, Debug)]
enum Jump {
    /// Fall through to the following instruction (relative offset zero).
    Fall,
    /// Jump to a named label.
    To(String),
}

impl Jump {
    fn of(label: Option<&str>) -> Self {
        match label {
            None => Self::Fall,
            Some(l) => Self::To(l.to_owned()),
        }
    }
}

#[derive(Clone, Debug)]
enum Item {
    Label(String),
    Insn {
        code: u16,
        jt: Jump,
        jf: Jump,
        k: u32,
    },
}

/// A symbolic program under construction.
///
/// Labels occupy no instruction slot; they name the instruction that follows
/// them. `None` as a jump target means "fall through", which is the same
/// encoding as a label on the next instruction.
#[derive(Clone, Debug, Default)]
pub struct Asm {
    items: Vec<Item>,
}

impl Asm {
    /// A program with no instructions.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Define `name` as the position of the next instruction emitted.
    pub fn label(&mut self, name: &str) -> &mut Self {
        self.items.push(Item::Label(name.to_owned()));
        self
    }

    /// `ld [offset]`: load a 32-bit word from the seccomp data block.
    pub fn ld_w_abs(&mut self, offset: u32) -> &mut Self {
        self.insn(CODE_LD_W_ABS, None, None, offset)
    }

    /// `jeq #k`: jump to `jt` when the accumulator equals `k`, else to `jf`.
    pub fn jeq(&mut self, k: u32, jt: Option<&str>, jf: Option<&str>) -> &mut Self {
        self.insn(CODE_JEQ_K, jt, jf, k)
    }

    /// `jset #k`: jump to `jt` when the accumulator has any bit of `k` set.
    pub fn jset(&mut self, k: u32, jt: Option<&str>, jf: Option<&str>) -> &mut Self {
        self.insn(CODE_JSET_K, jt, jf, k)
    }

    /// `ja label`: unconditional jump, 32-bit distance.
    pub fn ja(&mut self, label: &str) -> &mut Self {
        self.items.push(Item::Insn {
            code: CODE_JA,
            jt: Jump::To(label.to_owned()),
            jf: Jump::Fall,
            k: 0,
        });
        self
    }

    /// `ret #k`: end the program with verdict `k`.
    pub fn ret(&mut self, k: u32) -> &mut Self {
        self.insn(CODE_RET_K, None, None, k)
    }

    fn insn(&mut self, code: u16, jt: Option<&str>, jf: Option<&str>, k: u32) -> &mut Self {
        self.items.push(Item::Insn {
            code,
            jt: Jump::of(jt),
            jf: Jump::of(jf),
            k,
        });
        self
    }

    /// Resolve every label to a relative offset.
    ///
    /// # Errors
    ///
    /// Returns [`BpfError`] when a label is undefined or defined twice, when a
    /// conditional jump's distance exceeds 255, when a jump points backwards,
    /// or when the program exceeds `BPF_MAXINSNS`.
    pub fn assemble(&self) -> Result<Program, BpfError> {
        let mut labels: HashMap<&str, usize> = HashMap::new();
        let mut index = 0usize;
        for item in &self.items {
            match item {
                Item::Label(name) => {
                    if labels.insert(name.as_str(), index).is_some() {
                        return Err(BpfError::DuplicateLabel(name.clone()));
                    }
                }
                Item::Insn { .. } => index += 1,
            }
        }
        if index > MAX_INSNS {
            return Err(BpfError::TooManyInstructions(index));
        }

        let mut insns = Vec::with_capacity(index);
        let mut here = 0usize;
        for item in &self.items {
            let Item::Insn { code, jt, jf, k } = item else {
                continue;
            };
            let (jt_off, jf_off, k_out) = if *code == CODE_JA {
                // An unconditional jump carries its distance in `k`, so it is
                // not bounded by a byte.
                let target = resolve(jt, &labels)?;
                let distance = relative(here, target)?;
                (0u8, 0u8, u32::try_from(distance).expect("bounded above"))
            } else {
                (
                    byte_offset(here, resolve(jt, &labels)?)?,
                    byte_offset(here, resolve(jf, &labels)?)?,
                    *k,
                )
            };
            insns.push(SockFilter {
                code: *code,
                jt: jt_off,
                jf: jf_off,
                k: k_out,
            });
            here += 1;
        }
        Ok(Program { insns })
    }
}

fn resolve(jump: &Jump, labels: &HashMap<&str, usize>) -> Result<Option<usize>, BpfError> {
    match jump {
        Jump::Fall => Ok(None),
        Jump::To(name) => labels
            .get(name.as_str())
            .copied()
            .map(Some)
            .ok_or_else(|| BpfError::UnknownLabel(name.clone())),
    }
}

/// Distance from the instruction after `here` to `target`.
fn relative(here: usize, target: Option<usize>) -> Result<usize, BpfError> {
    let Some(target) = target else { return Ok(0) };
    let next = here + 1;
    target.checked_sub(next).ok_or(BpfError::BackwardJump {
        from: here,
        to: target,
    })
}

fn byte_offset(here: usize, target: Option<usize>) -> Result<u8, BpfError> {
    let distance = relative(here, target)?;
    u8::try_from(distance).map_err(|_| BpfError::JumpTooFar {
        from: here,
        to: target.unwrap_or(here),
    })
}

/// An assembled filter: instructions with resolved offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    insns: Vec<SockFilter>,
}

impl Program {
    /// The instructions, in program order.
    #[must_use]
    pub fn insns(&self) -> &[SockFilter] {
        &self.insns
    }

    /// Number of instructions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    /// Whether the program has no instructions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    /// The raw bytes the kernel reads, little-endian.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.insns.len() * 8);
        for insn in &self.insns {
            out.extend_from_slice(&insn.to_bytes());
        }
        out
    }

    /// `sha256:<hex>` over [`Program::to_bytes`]. This is the value a receipt
    /// records as the filter's identity.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let out = hasher.finalize();
        let mut hex = String::with_capacity(7 + out.len() * 2);
        hex.push_str("sha256:");
        for byte in out {
            use fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    /// One readable line per instruction, for tests and evidence files.
    #[must_use]
    pub fn disassemble(&self) -> Vec<String> {
        self.insns
            .iter()
            .enumerate()
            .map(|(i, insn)| {
                let body = match insn.code {
                    CODE_LD_W_ABS => format!("ld    [{}]", insn.k),
                    CODE_JEQ_K => format!(
                        "jeq   #0x{:08x}  jt {} jf {}",
                        insn.k,
                        target(i, insn.jt),
                        target(i, insn.jf)
                    ),
                    CODE_JSET_K => format!(
                        "jset  #0x{:08x}  jt {} jf {}",
                        insn.k,
                        target(i, insn.jt),
                        target(i, insn.jf)
                    ),
                    CODE_JA => format!("ja    {}", i + 1 + insn.k as usize),
                    CODE_RET_K => format!("ret   #0x{:08x}", insn.k),
                    other => format!("<unknown code 0x{other:04x}> k=0x{:08x}", insn.k),
                };
                format!("{i:04} {body}")
            })
            .collect()
    }

    /// A `sock_fprog` pointing at this program's instructions.
    ///
    /// The returned struct borrows `self`; it is only valid while `self`
    /// lives, which is why this is not `into_`.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn sock_fprog(&self) -> libc::sock_fprog {
        libc::sock_fprog {
            len: u16::try_from(self.insns.len()).expect("assemble() bounds the length"),
            filter: self.insns.as_ptr().cast::<libc::sock_filter>().cast_mut(),
        }
    }
}

fn target(index: usize, offset: u8) -> usize {
    index + 1 + offset as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Program {
        let mut asm = Asm::new();
        asm.ld_w_abs(4)
            .jeq(0xc000_003e, None, Some("deny"))
            .ld_w_abs(0)
            .jeq(101, Some("deny"), None)
            .ret(0x7fff_0000)
            .label("deny")
            .ret(0x0005_0001);
        asm.assemble().expect("tiny program assembles")
    }

    #[test]
    fn labels_resolve_to_relative_offsets() {
        let prog = tiny();
        assert_eq!(prog.len(), 6);
        // instruction 1 jumps to `deny` at index 5 => offset 5 - (1+1) = 3
        assert_eq!(prog.insns()[1].jf, 3);
        assert_eq!(prog.insns()[1].jt, 0, "fall-through encodes as zero");
        // instruction 3 jumps to `deny` at index 5 => offset 5 - (3+1) = 1
        assert_eq!(prog.insns()[3].jt, 1);
        assert_eq!(prog.insns()[3].jf, 0);
    }

    #[test]
    fn opcodes_match_the_linux_encoding() {
        assert_eq!(CODE_LD_W_ABS, 0x20);
        assert_eq!(CODE_JEQ_K, 0x15);
        assert_eq!(CODE_JSET_K, 0x45);
        assert_eq!(CODE_JA, 0x05);
        assert_eq!(CODE_RET_K, 0x06);
    }

    #[test]
    fn unconditional_jump_carries_its_distance_in_k() {
        let mut asm = Asm::new();
        asm.ja("end");
        for _ in 0..300 {
            asm.ret(0);
        }
        asm.label("end").ret(1);
        let prog = asm.assemble().expect("ja is not byte-bounded");
        assert_eq!(prog.insns()[0].code, CODE_JA);
        assert_eq!(prog.insns()[0].k, 300);
    }

    #[test]
    fn conditional_jump_beyond_a_byte_is_an_error_not_a_wrap() {
        let mut asm = Asm::new();
        asm.jeq(1, Some("end"), None);
        for _ in 0..300 {
            asm.ret(0);
        }
        asm.label("end").ret(1);
        assert_eq!(
            asm.assemble(),
            Err(BpfError::JumpTooFar { from: 0, to: 301 })
        );
    }

    #[test]
    fn backward_jump_is_refused() {
        let mut asm = Asm::new();
        asm.label("top").ret(0).ja("top");
        assert!(matches!(
            asm.assemble(),
            Err(BpfError::BackwardJump { from: 1, to: 0 })
        ));
    }

    #[test]
    fn undefined_label_is_an_error() {
        let mut asm = Asm::new();
        asm.jeq(1, Some("nowhere"), None).ret(0);
        assert_eq!(
            asm.assemble(),
            Err(BpfError::UnknownLabel("nowhere".to_owned()))
        );
    }

    #[test]
    fn duplicate_label_is_an_error() {
        let mut asm = Asm::new();
        asm.label("x").ret(0).label("x").ret(1);
        assert_eq!(
            asm.assemble(),
            Err(BpfError::DuplicateLabel("x".to_owned()))
        );
    }

    #[test]
    fn program_longer_than_the_kernel_limit_is_refused() {
        let mut asm = Asm::new();
        for _ in 0..=MAX_INSNS {
            asm.ret(0);
        }
        assert_eq!(
            asm.assemble(),
            Err(BpfError::TooManyInstructions(MAX_INSNS + 1))
        );
    }

    #[test]
    fn bytes_are_the_kernel_layout() {
        let insn = SockFilter {
            code: CODE_JEQ_K,
            jt: 3,
            jf: 4,
            k: 0xc000_003e,
        };
        assert_eq!(insn.to_bytes(), [0x15, 0x00, 3, 4, 0x3e, 0x00, 0x00, 0xc0]);
        assert_eq!(tiny().to_bytes().len(), 6 * 8);
    }

    #[test]
    fn digest_is_stable_for_a_fixed_program() {
        // Changing the program changes this value; that is the point of
        // recording it in a receipt. The expected digest was computed
        // independently of this code, from the six instructions the program
        // is meant to be, so it checks the encoding and not just itself.
        assert_eq!(
            tiny().to_bytes(),
            [
                0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, //
                0x15, 0x00, 0x00, 0x03, 0x3e, 0x00, 0x00, 0xc0, //
                0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
                0x15, 0x00, 0x01, 0x00, 0x65, 0x00, 0x00, 0x00, //
                0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, //
                0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, //
            ]
        );
        assert_eq!(
            tiny().digest(),
            "sha256:aa2b6a149b8556ea9bc9a06096d45249749dd04cb3d47f29a9d3cc49c5527b60"
        );
    }

    #[test]
    fn digest_changes_when_one_immediate_changes() {
        let mut asm = Asm::new();
        asm.ld_w_abs(4)
            .jeq(0xc000_003e, None, Some("deny"))
            .ld_w_abs(0)
            .jeq(102, Some("deny"), None) // 101 in `tiny`
            .ret(0x7fff_0000)
            .label("deny")
            .ret(0x0005_0001);
        assert_ne!(asm.assemble().unwrap().digest(), tiny().digest());
    }

    #[test]
    fn disassembly_names_absolute_targets() {
        let lines = tiny().disassemble();
        assert_eq!(lines.len(), 6);
        assert!(lines[1].contains("jt 2 jf 5"), "got {}", lines[1]);
        assert!(lines[4].starts_with("0004 ret"), "got {}", lines[4]);
    }
}
