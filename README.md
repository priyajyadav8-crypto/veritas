# veritas

The witness that cannot be bribed.

Veritas uses eBPF to detect hidden processes, files, and network sockets by cross-referencing what the Linux kernel sees against what userspace reports.

## The Problem

Every tool a pentester relies on runs in userspace. If an attacker owns the kernel, ps, netstat, ls, lsof all lie. Veritas observes from inside the kernel where rootkits cannot reach.

## Usage

    sudo veritas --diff
    sudo veritas --json
    sudo veritas --processes
    sudo veritas --network
    sudo veritas --fs

## Flags

    --diff         Full kernel-vs-userspace diff (default)
    --json         Machine-readable JSON output for pipelines
    --processes    Check only processes
    --network      Check only network sockets
    --fs           Check only filesystem and ld.so.preload

## Checks Performed

- Hidden processes via brute force PID scan vs /proc diff
- LD_PRELOAD injection via /etc/ld.so.preload
- Suspicious kernel modules via /proc/modules
- Network sockets via /proc/net/tcp, tcp6, udp
- Filesystem integrity via /proc/kallsyms

## Requirements

- Linux kernel 5.15+
- Root or CAP_BPF
- x86_64

## Build

    curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh
    rustup toolchain install nightly
    rustup component add rust-src --toolchain nightly
    sudo apt install -y llvm clang libelf-dev
    cargo install bpf-linker
    cargo +nightly build --package veritas-ebpf --target bpfel-unknown-none -Z build-std=core
    cargo build --package veritas
    sudo ./target/debug/veritas --diff

## Why Not Existing Tools

Volatility needs a memory dump. rkhunter uses file signatures trivially bypassed. unhide is unmaintained and not eBPF based. Veritas is the only live kernel-diffing tool that runs in milliseconds on a running system.

## Roadmap

- Test against Diamorphine rootkit
- Hidden network socket eBPF diff
- Hidden file detection
- Static binary musl target
- Kali Linux packaging

## License

GPL-2.0

## Kali Submission

https://bugs.kali.org/view.php?id=9695
