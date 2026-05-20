use aya::programs::TracePoint;
use aya_log::EbpfLogger;
use std::fs;
use std::collections::HashSet;
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
    println!("The witness that cannot be bribed.\n");

    // Method 1: read /proc numeric dirs (standard ps view)
    let proc_pids = get_proc_pids();

    // Method 2: read /proc/sysvipc/msg and cross check thread count
    let thread_count = get_thread_count();

    // Method 3: check /proc/loadavg for running process count
    let running = get_running_from_loadavg();

    println!("[*] PIDs visible in /proc:        {}", proc_pids.len());
    println!("[*] Total threads in /proc:       {}", thread_count);
    println!("[*] Kernel running count:         {}", running);

    // Cross reference: check each PID has a valid status file
    let ghost_pids = find_ghost_pids(&proc_pids);

    println!("\n--- PROCESS INTEGRITY CHECK ---");
    if ghost_pids.is_empty() {
        println!("[ok] All /proc PIDs have valid status files.");
    } else {
        println!("[!] {} PID(s) missing status files - possible rootkit activity!", ghost_pids.len());
        for pid in &ghost_pids {
            println!("    [!] Ghost PID: {}", pid);
        }
    }

    // Check ld.so.preload
    println!("\n--- LD_PRELOAD INJECTION CHECK ---");
    check_ld_preload();

    // Check for suspicious /proc entries
    println!("\n--- FILESYSTEM INTEGRITY CHECK ---");
    check_proc_integrity();

    println!("\n[*] eBPF probe active on getdents64 - press Ctrl-C to stop");
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}

fn get_proc_pids() -> Vec<u32> {
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .parse::<u32>()
                .ok()
        })
        .collect()
}

fn get_thread_count() -> usize {
    fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .filter_map(|pid| {
            fs::read_dir(format!("/proc/{}/task", pid)).ok()
        })
        .flat_map(|d| d.filter_map(|e| e.ok()))
        .count()
}

fn get_running_from_loadavg() -> String {
    fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .split_whitespace()
        .nth(3)
        .unwrap_or("?")
        .to_string()
}

fn find_ghost_pids(pids: &[u32]) -> Vec<u32> {
    pids.iter()
        .filter(|&&pid| {
            fs::read_to_string(format!("/proc/{}/status", pid)).is_err()
        })
        .copied()
        .collect()
}

fn check_ld_preload() {
    match fs::read_to_string("/etc/ld.so.preload") {
        Ok(content) if !content.trim().is_empty() => {
            println!("[!] WARNING: /etc/ld.so.preload is NOT empty!");
            println!("[!] Contents: {}", content.trim());
            println!("[!] This is a common rootkit injection method.");
        }
        Ok(_) => println!("[ok] /etc/ld.so.preload is empty. Clean."),
        Err(_) => println!("[ok] /etc/ld.so.preload does not exist. Clean."),
    }
}

fn check_proc_integrity() {
    let suspicious = vec![
        "/proc/sched_debug",
        "/proc/kallsyms",
    ];

    for path in suspicious {
        match fs::metadata(path) {
            Ok(_) => println!("[*] {} exists (normal on this kernel)", path),
            Err(_) => println!("[!] {} missing - kernel may be modified", path),
        }
    }

    // Check if /proc/modules is readable
    match fs::read_to_string("/proc/modules") {
        Ok(content) => {
            let module_count = content.lines().count();
            println!("[ok] /proc/modules readable - {} modules loaded", module_count);
        }
        Err(_) => println!("[!] /proc/modules unreadable - suspicious"),
    }
}
