//! Repository tasks that are not unit tests (jail-v1 §4).
//!
//! `cargo xtask i02-scan` once `.cargo/config.toml` carries the alias
//! `xtask = "run -p xtask --"`; `cargo run -p xtask -- i02-scan` always.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod conformance;
mod i02;
mod manifest;
mod stamp;

#[derive(Parser)]
#[command(name = "xtask", about = "Repository tasks for the ouro workspace")]
struct Cli {
    #[command(subcommand)]
    task: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Scan the execution core for vendor names (jail-v1 I02).
    I02Scan {
        /// Repository root; defaults to the current git worktree.
        #[arg(long, value_name = "DIR")]
        root: Option<PathBuf>,
    },
    /// Drive the conformance suite on the provisioned reference host.
    Conformance {
        #[arg(long, value_name = "HOST")]
        host: String,
        #[arg(long, value_name = "USER")]
        user: String,
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        #[arg(long, value_name = "PATH")]
        known_hosts: Option<PathBuf>,
        #[arg(
            long,
            value_name = "PATH",
            default_value = "docs/specs/jail-v1/conformance-manifest.toml"
        )]
        manifest: PathBuf,
        #[arg(long, value_name = "DIR", default_value = "evidence")]
        evidence: PathBuf,
        /// Remote build and test parallelism; the host has 4 vCPU shared.
        #[arg(long, default_value_t = 2)]
        jobs: u32,
        /// Keep the remote run directory even when the run passes.
        #[arg(long)]
        keep_remote: bool,
    },
}

fn main() -> ExitCode {
    match Cli::parse().task {
        Task::I02Scan { root } => i02_scan(root),
        Task::Conformance {
            host,
            user,
            key,
            known_hosts,
            manifest,
            evidence,
            jobs,
            keep_remote,
        } => {
            let worktree = conformance::worktree_root();
            let opts = conformance::Options {
                target: conformance::Target {
                    host,
                    user,
                    key,
                    known_hosts,
                },
                manifest: absolutise(&worktree, &manifest),
                evidence,
                host_manifest_script: worktree.join("docs/specs/jail-v1/host-manifest.sh"),
                worktree,
                jobs,
                keep_remote,
            };
            match conformance::drive(&opts) {
                Ok(report) if report.failures.is_empty() => {
                    println!(
                        "xtask conformance: evidence in {}",
                        report.evidence.display()
                    );
                    ExitCode::SUCCESS
                }
                Ok(report) => {
                    eprintln!(
                        "xtask conformance: {} problem(s); remote run directory {} kept",
                        report.failures.len(),
                        report.remote_dir
                    );
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("xtask conformance: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

fn absolutise(root: &std::path::Path, p: &std::path::Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        root.join(p)
    }
}

fn i02_scan(root: Option<PathBuf>) -> ExitCode {
    let base = root.unwrap_or_else(conformance::worktree_root);
    let scan = match i02::scan_roots(&base, i02::ROOTS) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask i02-scan: {e}");
            return ExitCode::FAILURE;
        }
    };
    for root in &scan.roots_absent {
        println!(
            "i02-scan: {} is absent (nothing scanned there)",
            root.display()
        );
    }
    for link in &scan.symlinks_skipped {
        println!(
            "i02-scan: {} is a symlink and was not followed",
            link.display()
        );
    }
    for hit in &scan.hits {
        println!("{hit}");
    }
    println!(
        "i02-scan: {} file(s) in {} root(s), {} hit(s)",
        scan.files_scanned,
        scan.roots_scanned.len(),
        scan.hits.len()
    );
    if scan.hits.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
