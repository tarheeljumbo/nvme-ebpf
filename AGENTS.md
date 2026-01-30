# AGENTS.md — nvme-guard (Codex / agent execution guide)

this file is instructions for an agentic coding system (codex-like) to implement **nvme-guard** safely and reproducibly.

## 0) prime directive: do not brick the host

this project touches NVMe control paths and boot-critical files. **the agent must never run destructive nvme operations** (format, sanitize, firmware download/activate, namespace create/delete) and must never write to real `/boot` or `/boot/efi` on the developer machine unless the user explicitly says so.

**assume the developer machine has exactly one drive and it is NVMe.** any mistake can cause data loss or an unbootable system.

### forbidden actions (hard ban)
- running `nvme format`, `nvme sanitize`, `nvme delete-ns`, `nvme create-ns`, `nvme fw-download`, `nvme fw-activate`
- writing raw blocks to any `/dev/nvme*`, including `dd`, `sgdisk`, `parted`, `wipefs`, `mkfs.*`, `cryptsetup` on nvme devices
- modifying `/boot`, `/boot/efi`, `/efi`, grub configs, initramfs, or EFI binaries on the real host
- enabling enforcement/blocking by default
- installing kernel modules, changing kernel parameters, or altering secure boot settings without explicit permission

### allowed actions (safe)
- compiling code (go + clang) and building bpf objects
- loading eBPF programs in **detect-only** mode
- reading metadata from `/proc`, `/sys`, `mountinfo`
- creating and writing files only under:
  - the project directory
  - `/tmp/nvme-guard-test/*`
  - a user-specified scratch directory
- integration tests must use **simulated targets** (see section 6)

---

## 1) development modes (must exist; agent must default to safe)

nvme-guard supports three runtime modes; codex must default to `detect`:

- `detect` (default): observe + alert only; never deny/terminate
- `dry-run-enforce`: compute “would block” decisions but do not block
- `enforce`: actually block actions (only if user explicitly enables)

the agent must implement a config parser that defaults to `mode: detect` if unset.

---

## 2) incremental implementation policy (no big bangs)

the agent must build in small, verifiable steps:

1) repo scaffold + `make build`
2) event schema + json output (no bpf yet)
3) add one sensor at a time:
   - nvme ioctl (tracepoints)
   - boot vfs (writes/rename/unlink) but **with path filter pointed at a test mount**
   - block raw (tracepoints) but **disabled by default**
4) add rules engine
5) add tests + harness
6) add docs + packaging

after each step, run:
- `go test ./...`
- `make build`
and only then proceed.

---

## 3) safe testing strategy (mandatory)

### 3.1 never test against real boot paths
all “boot-plane” logic must be testable against a **bind-mounted sandbox**:

- create a sandbox directory:
  - `/tmp/nvme-guard-test/boot`
  - `/tmp/nvme-guard-test/boot-efi`
- bind mount it to a fake mountpoint used by config:
  - config uses `paths.boot_prefixes: ["/mnt/nvme-guard-boot", "/mnt/nvme-guard-boot-efi"]`
- the harness bind-mounts:
  - `/tmp/nvme-guard-test/boot` → `/mnt/nvme-guard-boot`
  - `/tmp/nvme-guard-test/boot-efi` → `/mnt/nvme-guard-boot-efi`

the shipped example config must point to **real** `/boot` prefixes, but the integration harness must never do so on the host.

### 3.2 nvme ioctl tests must be non-destructive
ioctl tests must not issue any nvme admin command payloads. allowed tests:

- open a harmless file descriptor and issue a dummy ioctl to exercise the tracepoint path
- open `/dev/null` and ioctl it
- if a real `/dev/nvme*` fd is opened, the test must not use NVMe ioctl request ids; it should only verify fd path resolution code in userspace.

### 3.3 block layer tests must not write to nvme
block tests must be disabled by default and can only run if an environment flag is set:
- `NVME_GUARD_ENABLE_BLOCK_TESTS=1`

when enabled, tests should target a loop device:
- create a loopback file in `/tmp`
- attach it with `losetup`
- do **safe** writes to the loop device
- verify tracepoint plumbing
the agent must not attempt to make loop devices look like nvme; only validate the code path.

---

## 4) runtime guardrails (must be implemented)

### 4.1 “host safety fuse”
implement a safety fuse in userspace:

- detect if the system appears to have a single root disk and it is nvme (heuristic: root mount is on `/dev/nvme*`)
- if so, and if config `mode=enforce`, the daemon must refuse to start unless:
  - `config.safety.allow_enforce_on_single_nvme_root: true`
  - AND an explicit `--i-understand-this-can-break-my-machine` cli flag is provided

default must be refusal + explicit error message.

### 4.2 “boot path write protection”
if config boot prefixes include real `/boot` or `/boot/efi`, then:
- baseline hashing is allowed (read-only)
- no tests or harness scripts may write there
- integration harness must refuse to run unless prefixes are sandboxed

---

## 5) coding standards for the agent

- no shell scripts that run destructive commands
- every exec of external commands must go through a wrapper that logs the exact command and refuses banned tokens (`nvme format`, `dd of=/dev/nvme`, etc.)
- all paths must be joined safely; no `rm -rf` outside sandbox
- bpf code must be CO-RE friendly (BTF) and keep structs fixed-size
- prefer tracepoints over kprobes for stability; only use kprobes if no tracepoint alternative exists

---

## 6) integration harness requirements

ship `tests/integration/harness.sh` with these properties:

- creates sandbox directories under `/tmp/nvme-guard-test`
- bind-mounts them to `/mnt/nvme-guard-boot*`
- runs daemon in detect mode with a **test config** (stored in `tests/integration/test-config.yaml`)
- performs:
  - write/rename/unlink actions under sandbox boot mountpoints
  - verifies daemon emitted events (grep json keys)
- unmounts and cleans up
- must exit nonzero on any failure
- must not require network access

the harness must start with a loud banner describing what it will and will not touch.

---

## 7) documentation updates (agent must maintain)

when adding features, codex must update:
- `docs/design_notes.md` (high-level)
- `docs/event_schema.md` (field-level changes, version bump)
- `docs/threat_model.md` (new behaviors/false positives)

---

## 8) “done” definition for codex

codex should stop when all are true:

- `make build` succeeds
- `go test ./...` passes
- `make bpf` succeeds
- `tests/integration/harness.sh` runs successfully in a privileged environment **without touching real /boot or /dev/nvme**
- daemon runs in detect mode and logs:
  - at least one nvme ioctl tracepoint event (from harmless ioctl activity)
  - at least one boot vfs event (from sandboxed write)
- config validation works; unsafe enforce on single nvme root is refused by default

---

## 9) explicit user confirmation gates (agent must ask; do not proceed automatically)

the agent must not:
- enable `enforce` mode
- expand tests to use real `/dev/nvme*`
- write to real `/boot` or `/boot/efi`
unless the user explicitly instructs it in a subsequent message.

---
