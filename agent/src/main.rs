mod db;

use clap::{Parser, Subcommand};
use core::{FileMeta, Snapshot, compare_snapshots};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::Path;

use jwalk::WalkDir;
use rayon::prelude::*;
use tracing::{debug, debug_span, error, info, warn};
use tracing_appender::rolling;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

const SNAPSHOT_FILE: &str = ".fim_snapshot.json";

#[derive(Parser, Debug)]
#[command(author, version, about = "File Integrity Monitor", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Init { dir: String },
    Check { dir: String },
}

fn init_logging() -> tracing_appender::non_blocking::WorkerGuard {
    let file_appender = rolling::daily("logs", "fim.log");

    let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);

    let console_layer = fmt::layer().compact().with_thread_ids(true);

    let file_layer = fmt::layer()
        .with_writer(non_blocking_writer)
        .with_ansi(false)
        .with_thread_ids(true);

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    guard
}

fn compute_blake3(filepath: &str, size: u64) -> io::Result<String> {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    if size > 16 * 1024 * 1024 {
        hasher.update_mmap_rayon(filepath)?;
    } else {
        let file = File::open(filepath)?;
        hasher.update_reader(file)?;
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn build_snapshot<P: AsRef<Path>>(dir: P) -> std::io::Result<Snapshot> {
    let snapshot: Snapshot = WalkDir::new(dir)
        .skip_hidden(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter(|entry| entry.file_name() != SNAPSHOT_FILE)
        .par_bridge()
        .filter_map(|entry| {
            let path: std::path::PathBuf = entry.path();

            let canonical_path: std::path::PathBuf = match dunce::canonicalize(&path) {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = ?e, path = %path.display(), "Failed to canonicalize path");
                    return None;
                }
            };
            let path_str: String = canonical_path.to_str()?.to_string();

            let _span = debug_span!("process_file", path = %path_str).entered();

            let metadata: fs::Metadata = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = ?e, "Failed to get metadata");
                    return None;
                }
            };
            let size: u64 = metadata.len();

            let modified: std::time::SystemTime = match metadata.modified() {
                Ok(m) => m,
                Err(e) => {
                    debug!(error = ?e, "Failed to fet modified time");
                    return None;
                }
            };

            debug!("Computing hash...");
            let hash: Option<String> = match compute_blake3(&path_str, size) {
                Ok(h) => Some(h),
                Err(e) => {
                    warn!(error = ?e, "Failed to compute hash, skipping hash field");
                    None
                }
            };

            Some((
                path_str,
                FileMeta {
                    size,
                    modified,
                    hash,
                },
            ))
        })
        .collect();

    Ok(snapshot)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = init_logging();

    let cli: Cli = Cli::parse();

    match &cli.command {
        Command::Init { dir } => {
            info!(target_dir = dir, "Building baseline snapshot...");

            let snap: BTreeMap<String, FileMeta> = match build_snapshot(dir) {
                Ok(s) => s,
                Err(e) => {
                    error!(error = ?e, "Snapshot generation failed");
                    return Err(e.into());
                }
            };

            let json: String = serde_json::to_string_pretty(&snap)?;

            if let Err(e) = fs::write(SNAPSHOT_FILE, json) {
                error!(error = ?e, file = SNAPSHOT_FILE, "Failed to write snapshot to disk");
                return Err(e.into());
            };

            info!(
                file = SNAPSHOT_FILE,
                scanned = snap.len(),
                "Snapshot successfully saved"
            );
        }
        Command::Check { dir } => {
            if !Path::new(SNAPSHOT_FILE).exists() {
                error!("No snapshot found. Run 'init' first");
                return Err("No snapshot found".into());
            }

            info!(target_dir = dir, "Scanning current directory...");

            let data: String = fs::read_to_string(SNAPSHOT_FILE)?;
            let old_snap: Snapshot = serde_json::from_str(&data)?;

            let new_snap: BTreeMap<String, FileMeta> = build_snapshot(dir)?;
            let total_scanned = new_snap.len();

            let diff: BTreeMap<String, core::Alert> = compare_snapshots(&old_snap, &new_snap);

            if diff.is_empty() {
                info!(
                    scanned = total_scanned,
                    "Integrity check passes: No unauthorized changes."
                );
            } else {
                error!(
                    scanned = total_scanned,
                    alerts = diff.len(),
                    "TAMPERING DETECTED!"
                );
                for (path, alert) in &diff {
                    warn!(alert_type = ?alert, file = path, "Unauthorized change")
                }
            }
        }
    }
    Ok(())
}
