use aya::programs::TracePoint;
use aya_log::EbpfLogger;
use std::fs;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let mut ebpf = aya::Ebpf::load(include_bytes!(
        "../../target/bpfel-unknown-none/debug/veritas"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        eprintln!("Logger init failed: {e}");
    }

    let program: &mut TracePoint = ebpf
        .program_mut("veritas")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_getdents64")?;

    println!("=== VERITAS - Kernel Truth Engine ===");
    println!("Monitoring for hidden processes...");

    let proc_pids = count_proc_pids();
    println!("[*] /proc reports {} processes", proc_pids);
    println!("[*] Watching getdents64 - press Ctrl-C to stop");

    signal::ctrl_c().await?;

    let final_pids = count_proc_pids();
    println!("[*] Final /proc PID count: {}", final_pids);
    println!("[ok] Scan complete.");
    println!("Exiting...");
    Ok(())
}

fn count_proc_pids() -> usize {
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .chars()
                .all(|c| c.is_numeric())
        })
        .count()
}
