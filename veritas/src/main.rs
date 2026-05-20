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

    // --- Get all known threads from visible processes ---
    let known_threads = get_all_threads(&proc_pids);

    // --- DIFF: brute force vs /proc, excluding known threads ---
    let truly_hidden: Vec<u32> = brute_pids
        .difference(&proc_pids)
        .copied()
        .filter(|pid| !known_threads.contains(pid))
        .collect();

    println!("[*] /proc readdir sees:           {} processes", proc_pids.len());
    println!("[*] Brute force scan finds:       {} PIDs", brute_pids.len());
    println!("[*] Known legitimate threads:     {}", known_threads.len());

    // --- RESULTS ---
    println!("\n--- PROCESS INTEGRITY CHECK ---");
    if truly_hidden.is_empty() {
        println!("[ok] No hidden processes detected.");
        println!("[ok] All unmatched PIDs are legitimate threads.");
    } else {
        println!("[!] {} TRULY HIDDEN PROCESS(ES) DETECTED!", truly_hidden.len());
        println!("[!] These PIDs exist in kernel but are NOT threads of any visible process:");
        for pid in &truly_hidden {
            let name = get_process_name(*pid).unwrap_or("unknown".to_string());
            let cmdline = get_cmdline(*pid).unwrap_or("no cmdline".to_string());
            println!("    [!] PID {} - name: {} - cmd: {}", pid, name, cmdline);
        }
        println!("\n[!] THIS MACHINE MAY BE COMPROMISED.");
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

    // --- KERNEL MODULES CHECK ---
    println!("\n--- KERNEL MODULES CHECK ---");
    check_kernel_modules();

    println!("\n[*] eBPF probe active on getdents64 - press Ctrl-C to stop");
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

fn get_all_threads(pids: &HashSet<u32>) -> HashSet<u32> {
    let mut threads = HashSet::new();
    for &pid in pids {
        if let Ok(entries) = fs::read_dir(format!("/proc/{}/task", pid)) {
            for entry in entries.filter_map(|e| e.ok()) {
                if let Ok(tid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    threads.insert(tid);
                }
            }
        }
    }
    threads
}

fn get_process_name(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}

fn get_cmdline(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string())
        .filter(|s| !s.is_empty())
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
}

fn check_kernel_modules() {
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        let suspicious_keywords = vec![
            "rootkit", "hide", "stealth", "ghost",
            "diamorphine", "reptile", "azazel", "necurs"
        ];
        let mut found_suspicious = false;
        for line in content.lines() {
            let lower = line.to_lowercase();
            for keyword in &suspicious_keywords {
                if lower.contains(keyword) {
                    println!("[!] SUSPICIOUS MODULE: {}", line);
                    found_suspicious = true;
                }
            }
        }
        if !found_suspicious {
            println!("[ok] No suspicious kernel modules detected.");
        }
    }
}
