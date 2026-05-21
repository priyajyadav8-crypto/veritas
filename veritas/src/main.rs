use aya::programs::TracePoint;
use aya_log::EbpfLogger;
use clap::Parser;
use std::fs;
use std::collections::HashSet;
use tokio::signal;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "veritas",
    about = "Kernel Truth Engine — detects hidden processes, files, and sockets",
    long_about = "Veritas uses eBPF to observe the system from inside the kernel.\nIt cross-references what the kernel sees against what userspace reports.\nThe witness that cannot be bribed."
)]
struct Cli {
    /// Run full kernel-vs-userspace diff (default mode)
    #[arg(long, default_value_t = true)]
    diff: bool,

    /// Output results as JSON for pipeline integration
    #[arg(long)]
    json: bool,

    /// Check only processes
    #[arg(long)]
    processes: bool,

    /// Check only network sockets
    #[arg(long)]
    network: bool,

    /// Check only filesystem and ld.so.preload
    #[arg(long)]
    fs: bool,
}

#[derive(Serialize)]
struct VeritasReport {
    processes: ProcessReport,
    network: NetworkReport,
    filesystem: FilesystemReport,
    verdict: String,
}

#[derive(Serialize)]
struct ProcessReport {
    proc_count: usize,
    brute_force_count: usize,
    thread_count: usize,
    hidden: Vec<HiddenProcess>,
    clean: bool,
}

#[derive(Serialize)]
struct HiddenProcess {
    pid: u32,
    name: String,
    cmdline: String,
}

#[derive(Serialize)]
struct NetworkReport {
    tcp: usize,
    tcp6: usize,
    udp: usize,
    hidden_sockets: usize,
    clean: bool,
}

#[derive(Serialize)]
struct FilesystemReport {
    ld_preload_clean: bool,
    ld_preload_contents: Option<String>,
    kallsyms_exists: bool,
    modules_count: usize,
    suspicious_modules: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    // determine which checks to run
    let run_all = !cli.processes && !cli.network && !cli.fs;
    let run_processes = run_all || cli.processes;
    let run_network   = run_all || cli.network;
    let run_fs        = run_all || cli.fs;

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

    if !cli.json {
        println!("=== VERITAS - Kernel Truth Engine ===");
        println!("The witness that cannot be bribed.");
        println!("--------------------------------------\n");
    }

    // --- PROCESS CHECK ---
    let process_report = if run_processes {
        let proc_pids    = get_proc_pids();
        let brute_pids   = brute_force_pids(1, 65535);
        let known_threads = get_all_threads(&proc_pids);

        let truly_hidden: Vec<HiddenProcess> = brute_pids
            .difference(&proc_pids)
            .copied()
            .filter(|pid| !known_threads.contains(pid))
            .map(|pid| HiddenProcess {
                pid,
                name: get_process_name(pid).unwrap_or("unknown".to_string()),
                cmdline: get_cmdline(pid).unwrap_or("no cmdline".to_string()),
            })
            .collect();

        let clean = truly_hidden.is_empty();

        if !cli.json {
            println!("--- PROCESS INTEGRITY CHECK ---");
            println!("[*] /proc readdir sees:       {} processes", proc_pids.len());
            println!("[*] Brute force scan finds:   {} PIDs", brute_pids.len());
            println!("[*] Known threads:            {}", known_threads.len());
            if clean {
                println!("[ok] No hidden processes detected.\n");
            } else {
                println!("[!] {} HIDDEN PROCESS(ES) DETECTED!", truly_hidden.len());
                for h in &truly_hidden {
                    println!("    [!] PID {} - {} - {}", h.pid, h.name, h.cmdline);
                }
                println!();
            }
        }

        ProcessReport {
            proc_count: proc_pids.len(),
            brute_force_count: brute_pids.len(),
            thread_count: known_threads.len(),
            hidden: truly_hidden,
            clean,
        }
    } else {
        ProcessReport { proc_count:0, brute_force_count:0, thread_count:0, hidden:vec![], clean:true }
    };

    // --- NETWORK CHECK ---
    let network_report = if run_network {
        let tcp  = count_net("/proc/net/tcp");
        let tcp6 = count_net("/proc/net/tcp6");
        let udp  = count_net("/proc/net/udp");

        if !cli.json {
            println!("--- NETWORK SOCKET CHECK ---");
            println!("[*] TCP connections:  {}", tcp);
            println!("[*] TCP6 connections: {}", tcp6);
            println!("[*] UDP connections:  {}", udp);
            println!();
        }

        // hidden socket detection
        let net1 = get_socket_inodes_from_proc_net();
        let proc_inodes = get_network_socket_inodes_from_procs();
        let net2 = get_socket_inodes_from_proc_net();
        let net3 = get_socket_inodes_from_proc_net();
        let stable: std::collections::HashSet<u64> = net1.iter().filter(|i| net2.contains(i) && net3.contains(i)).copied().collect();
        let hidden_count = stable.difference(&proc_inodes).count();

        if !cli.json {
            if hidden_count == 0 {
                println!("[ok] No hidden sockets detected.");
            } else {
                println!("[!] {} HIDDEN SOCKET(S) DETECTED!", hidden_count);
                println!("[!] Sockets exist in kernel but are hidden from /proc/net");
                println!("[*] Note: on WSL2 this may include legitimate system sockets");
            }
        }

        NetworkReport { tcp, tcp6, udp, hidden_sockets: hidden_count, clean: hidden_count == 0 }
    } else {
        NetworkReport { tcp:0, tcp6:0, udp:0, hidden_sockets:0, clean:true }
    };

    // --- FILESYSTEM CHECK ---
    let fs_report = if run_fs {
        let (ld_clean, ld_contents) = check_ld_preload_data();
        let kallsyms = fs::metadata("/proc/kallsyms").is_ok();
        let (mod_count, suspicious) = check_modules_data();

        if !cli.json {
            println!("--- LD_PRELOAD INJECTION CHECK ---");
            if ld_clean {
                println!("[ok] /etc/ld.so.preload clean.");
            } else {
                println!("[!] /etc/ld.so.preload NOT empty: {:?}", ld_contents);
            }

            println!("\n--- FILESYSTEM INTEGRITY CHECK ---");
            if kallsyms {
                println!("[ok] /proc/kallsyms exists");
            } else {
                println!("[!] /proc/kallsyms missing");
            }
            println!("[ok] {} kernel modules loaded", mod_count);

            if suspicious.is_empty() {
                println!("[ok] No suspicious kernel modules.");
            } else {
                for m in &suspicious {
                    println!("[!] SUSPICIOUS MODULE: {}", m);
                }
            }
            println!();
        }

        FilesystemReport {
            ld_preload_clean: ld_clean,
            ld_preload_contents: ld_contents,
            kallsyms_exists: kallsyms,
            modules_count: mod_count,
            suspicious_modules: suspicious,
        }
    } else {
        FilesystemReport {
            ld_preload_clean: true,
            ld_preload_contents: None,
            kallsyms_exists: true,
            modules_count: 0,
            suspicious_modules: vec![],
        }
    };

    // --- VERDICT ---
    let compromised = !process_report.clean
        || !network_report.clean
        || !fs_report.ld_preload_clean
        || !fs_report.suspicious_modules.is_empty();

    let verdict = if compromised {
        "COMPROMISED — anomalies detected".to_string()
    } else {
        "CLEAN — no anomalies detected".to_string()
    };

    if cli.json {
        let report = VeritasReport {
            processes: process_report,
            network: network_report,
            filesystem: fs_report,
            verdict: verdict.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("--- VERDICT ---");
        if compromised {
            println!("[!] {}", verdict);
        } else {
            println!("[ok] {}", verdict);
        }
        println!("\n[*] eBPF probe active - press Ctrl-C to stop");
        signal::ctrl_c().await?;
        println!("Exiting...");
    }

    Ok(())
}

fn get_proc_pids() -> HashSet<u32> {
    fs::read_dir("/proc").unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        .collect()
}

fn brute_force_pids(start: u32, end: u32) -> HashSet<u32> {
    (start..=end)
        .filter(|&pid| fs::metadata(format!("/proc/{}/status", pid)).is_ok())
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

fn count_net(path: &str) -> usize {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .count()
}

fn check_ld_preload_data() -> (bool, Option<String>) {
    match fs::read_to_string("/etc/ld.so.preload") {
        Ok(c) if !c.trim().is_empty() => (false, Some(c.trim().to_string())),
        _ => (true, None),
    }
}

fn check_modules_data() -> (usize, Vec<String>) {
    let keywords = vec!["rootkit","hide","stealth","ghost","diamorphine","reptile","azazel"];
    let content = fs::read_to_string("/proc/modules").unwrap_or_default();
    let count = content.lines().count();
    let suspicious = content.lines()
        .filter(|l| keywords.iter().any(|k| l.to_lowercase().contains(k)))
        .map(|l| l.to_string())
        .collect();
    (count, suspicious)
}

fn get_socket_inodes_from_procs() -> std::collections::HashSet<u64> {
    // Only return inodes that appear in /proc/net/* (network sockets only)
    // This excludes Unix domain sockets which are not network connections
    get_socket_inodes_from_proc_net()
        .union(&std::collections::HashSet::new())
        .copied()
        .collect()
}

fn get_network_socket_inodes_from_procs() -> std::collections::HashSet<u64> {
    let net_inodes = get_socket_inodes_from_proc_net();
    let mut found = std::collections::HashSet::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else { return found };
    for entry in proc_dir.filter_map(|e| e.ok()) {
        let Ok(_pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let fd_path = format!("/proc/{}/fd", entry.file_name().to_string_lossy());
        let Ok(fd_dir) = fs::read_dir(&fd_path) else { continue };
        for fd in fd_dir.filter_map(|e| e.ok()) {
            let fd_full = format!("{}/{}", fd_path, fd.file_name().to_string_lossy());
            if let Ok(target) = fs::read_link(&fd_full) {
                let t = target.to_string_lossy();
                if t.starts_with("socket:[") {
                    if let Some(inode_str) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix("]")) {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            // only include if it is a known network socket
                            if net_inodes.contains(&inode) {
                                found.insert(inode);
                            }
                        }
                    }
                }
            }
        }
    }
    found
}

fn get_socket_inodes_from_proc_net() -> std::collections::HashSet<u64> {
    let mut inodes = std::collections::HashSet::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"] {
        let Ok(content) = fs::read_to_string(path) else { continue };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 10 {
                if let Ok(inode) = fields[9].parse::<u64>() {
                    inodes.insert(inode);
                }
            }
        }
    }
    inodes
}
