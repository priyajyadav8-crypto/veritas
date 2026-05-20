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
    println!("The witness that cannot be bribed.");
    println!("--------------------------------------\n");

    // --- METHOD 1: standard /proc readdir ---
    let proc_pids = get_proc_pids();

    // --- METHOD 2: brute force PID scan ---
    let brute_pids = brute_force_pids(1, 65535);

    // --- METHOD 3: /proc/sched list ---
    let sched_pids = get_sched_pids();

    println!("[*] Method 1 - /proc readdir:     {} PIDs", proc_pids.len());
    println!("[*] Method 2 - brute force scan:  {} PIDs", brute_pids.len());
    println!("[*] Method 3 - /proc/sched:       {} PIDs", sched_pids.len());

    // --- DIFF: brute force vs /proc ---
    let hidden_from_proc: Vec<u32> = brute_pids
        .difference(&proc_pids)
        .copied()
        .collect();

    // --- DIFF: sched vs /proc ---
    let hidden_from_sched: Vec<u32> = sched_pids
        .difference(&proc_pids)
        .copied()
        .collect();

    // --- RESULTS ---
    println!("\n--- PROCESS INTEGRITY CHECK ---");
    if hidden_from_proc.is_empty() && hidden_from_sched.is_empty() {
        println!("[ok] No hidden processes detected.");
        println!("[ok] All methods agree on process count.");
    } else {
        if !hidden_from_proc.is_empty() {
            println!("[!] {} HIDDEN PROCESS(ES) DETECTED via brute force!", hidden_from_proc.len());
            for pid in &hidden_from_proc {
                let name = get_process_name(*pid).unwrap_or("unknown".to_string());
                println!("    [!] PID {} - {} (visible to kernel, hidden from /proc)", pid, name);
            }
        }
        if !hidden_from_sched.is_empty() {
            println!("[!] {} HIDDEN PROCESS(ES) DETECTED via sched!", hidden_from_sched.len());
            for pid in &hidden_from_sched {
                let name = get_process_name(*pid).unwrap_or("unknown".to_string());
                println!("    [!] PID {} - {} (in scheduler, hidden from /proc)", pid, name);
            }
        }
    }

    // --- LD_PRELOAD CHECK ---
    println!("\n--- LD_PRELOAD INJECTION CHECK ---");
    check_ld_preload();

    // --- NETWORK CHECK ---
    println!("\n--- NETWORK SOCKET CHECK ---");
    check_network();

    // --- FILESYSTEM CHECK ---
    println!("\n--- FILESYSTEM INTEGRITY CHECK ---");
    check_proc_integrity();

    println!("\n[*] eBPF probe active - press Ctrl-C to stop");
    signal::ctrl_c().await?;
    println!("Exiting...");
    Ok(())
}

fn get_proc_pids() -> HashSet<u32> {
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

fn brute_force_pids(start: u32, end: u32) -> HashSet<u32> {
    (start..=end)
        .filter(|&pid| {
            fs::metadata(format!("/proc/{}/status", pid)).is_ok()
        })
        .collect()
}

fn get_sched_pids() -> HashSet<u32> {
    let mut pids = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/sched_debug") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                if let Ok(pid) = parts[3].trim_matches(',').parse::<u32>() {
                    pids.insert(pid);
                }
            }
        }
    }
    // fallback: use /proc/*/stat
    if pids.is_empty() {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid)) {
                        if !stat.is_empty() {
                            pids.insert(pid);
                        }
                    }
                }
            }
        }
    }
    pids
}

fn get_process_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
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

fn check_network() {
    // Compare /proc/net/tcp entries vs ss output
    match fs::read_to_string("/proc/net/tcp") {
        Ok(content) => {
            let count = content.lines().skip(1).filter(|l| !l.trim().is_empty()).count();
            println!("[*] /proc/net/tcp reports {} TCP connections", count);
        }
        Err(_) => println!("[!] /proc/net/tcp unreadable - suspicious"),
    }
    match fs::read_to_string("/proc/net/tcp6") {
        Ok(content) => {
            let count = content.lines().skip(1).filter(|l| !l.trim().is_empty()).count();
            println!("[*] /proc/net/tcp6 reports {} TCP6 connections", count);
        }
        Err(_) => println!("[!] /proc/net/tcp6 unreadable"),
    }
    match fs::read_to_string("/proc/net/udp") {
        Ok(content) => {
            let count = content.lines().skip(1).filter(|l| !l.trim().is_empty()).count();
            println!("[*] /proc/net/udp reports {} UDP connections", count);
        }
        Err(_) => println!("[!] /proc/net/udp unreadable"),
    }
}

fn check_proc_integrity() {
    match fs::metadata("/proc/kallsyms") {
        Ok(_) => println!("[ok] /proc/kallsyms exists"),
        Err(_) => println!("[!] /proc/kallsyms missing - kernel may be modified"),
    }
    match fs::read_to_string("/proc/modules") {
        Ok(content) => {
            let count = content.lines().count();
            println!("[ok] /proc/modules readable - {} modules loaded", count);
        }
        Err(_) => println!("[!] /proc/modules unreadable - suspicious"),
    }
    match fs::metadata("/proc/sched_debug") {
        Ok(_) => println!("[ok] /proc/sched_debug exists"),
        Err(_) => println!("[*] /proc/sched_debug missing (normal on WSL2)"),
    }
}
