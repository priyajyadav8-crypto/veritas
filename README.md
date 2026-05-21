# veritas

<div align="center">
![License](https://img.shields.io/badge/license-GPL--2.0-red)
![Kernel](https://img.shields.io/badge/kernel-5.15%2B-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)
![eBPF](https://img.shields.io/badge/eBPF-Aya-green)
![Binary](https://img.shields.io/badge/binary-2.7MB%20static-lightgrey)

**A kernel-truth engine that detects hidden processes, network sockets, and files using eBPF — from inside the Linux kernel where rootkits cannot reach.**

</div>

---

## The Problem

Every tool a penetration tester or incident responder relies on runs in userspace:
If an attacker owns the kernel, every one of those tools becomes a liar.
A rootkit can hide processes, files, and network connections, and nothing in userspace will tell you the truth.

**Veritas solves this.**

---

## How It Works

Veritas uses eBPF to attach probes directly to kernel functions — below userspace, below the rootkit's hooks. It then cross-references what the kernel actually sees against what userspace reports.
A rootkit can lie to /proc. It cannot lie to an eBPF probe sitting inside the kernel before the rootkit's hooks run.

---

## Proof — Diamorphine Rootkit Detected

Tested against the **Diamorphine** kernel rootkit on Debian 13 (kernel 6.12.88).

**Step 1 — Hide a process with Diamorphine:**
```bash
sleep 1000 &          # PID 9201
kill -31 9201         # send signal to hide it
ps aux | grep sleep   # process is gone from userspace
```

**Step 2 — Run veritas:**
**ps** could not see PID 9201. **Veritas caught it.**

JSON proof:
```json
{
  "processes": {
    "proc_count": 191,
    "brute_force_count": 726,
    "hidden": [
      {
        "pid": 9201,
        "name": "sleep",
        "cmdline": "sleep 1000"
      }
    ],
    "clean": false
  },
  "verdict": "COMPROMISED — anomalies detected"
}
```

---

## Usage

```bash
# Full kernel-vs-userspace diff (default)
sudo veritas --diff

# Machine-readable JSON for SIEM/pipeline integration
sudo veritas --json

# Check only processes
sudo veritas --processes

# Check only network sockets
sudo veritas --network

# Check only filesystem and LD_PRELOAD
sudo veritas --fs
```

### Sample Output on a Clean System
---

## What Veritas Checks

| Check | Method | Detects |
|-------|--------|---------|
| Hidden processes | Brute force PID scan vs /proc diff | Diamorphine, Reptile, any PID-hiding rootkit |
| Hidden network sockets | Socket inode cross-reference | Backdoors hiding on open ports |
| LD_PRELOAD injection | /etc/ld.so.preload read | Library injection rootkits |
| Kernel modules | /proc/modules keyword scan | Known rootkit module names |
| Critical file permissions | Direct stat checks | Tampered /etc/passwd, /etc/shadow |
| Suspicious paths | Path existence checks | Hidden files in /tmp, /dev/shm |
| PID 1 library maps | /proc/1/maps scan | Injected libraries in init process |

---

## Why Not Existing Tools

| Tool | Approach | Limitation |
|------|----------|------------|
| Volatility | Memory forensics | Requires offline memory dump |
| rkhunter | File signatures | Trivially bypassable |
| chkrootkit | Signature scan | Runs in userspace, can be blinded |
| unhide | Process diffing | Unmaintained, not eBPF-based |
| **veritas** | Live eBPF kernel diff | Operates below rootkit hooks |

---

## Requirements

- Linux kernel **5.15+** (6.x recommended)
- **Root** or CAP_BPF capability
- Architecture: **x86_64**

---

## Installation

### Download Static Binary

Download the prebuilt 2.7MB static binary from releases. No dependencies required.

```bash
chmod +x veritas
sudo ./veritas --diff
```

### Build from Source

```bash
# Install Rust nightly
curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly

# Install dependencies
sudo apt install -y llvm clang libelf-dev musl-tools

# Install eBPF linker
cargo install bpf-linker

# Build eBPF program
cargo +nightly build --package veritas-ebpf --target bpfel-unknown-none -Z build-std=core

# Build static release binary
cargo build --package veritas --target x86_64-unknown-linux-musl --release

# Run
sudo ./target/x86_64-unknown-linux-musl/release/veritas --diff
```

---

## Pipeline Integration

```bash
# Pipe to jq
sudo veritas --json | jq .verdict

# Cron job for continuous monitoring
*/15 * * * * sudo veritas --json >> /var/log/veritas.log

# Ship to central logging
sudo veritas --json | curl -X POST https://your-siem/ingest -d @-
```

---

## Technical Architecture
**Stack:**
- Language: Rust (nightly)
- eBPF library: Aya (pure Rust, no libbpf C dependency)
- Serialization: serde + serde_json
- Build target: x86_64-unknown-linux-musl (static binary, 2.7MB)
- Minimum kernel: 5.15

---

## Roadmap

- [x] Hidden process detection
- [x] Hidden network socket detection
- [x] LD_PRELOAD injection detection
- [x] Kernel module scanning
- [x] Critical path integrity checks
- [x] JSON output for pipeline integration
- [x] Static binary build
- [x] Man page
- [ ] Daemon mode for continuous monitoring
- [ ] Centralized fleet reporting
- [ ] Additional rootkit signatures

---

## License and Copyright
This project is licensed under the **GNU General Public License v2.0**.
See the LICENSE-GPL2 file for full terms.

---

## Author

**Created and maintained by Priyaj Yadav**

GitHub: [@priyajyadav8-crypto](https://github.com/priyajyadav8-crypto)

---

## Contributing

Issues and pull requests are welcome.
Please open an issue before submitting a large change.

---

<div align="center">
<sub>veritas — The witness that cannot be bribed.</sub>
</div>
