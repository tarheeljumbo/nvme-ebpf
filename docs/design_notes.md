## technical specification: **nvme-guard** (nvme control-plane + boot-plane persistence detector)

### 0) objective

build a host-based detector (and optional enforcer) for two persistence-adjacent classes of activity on linux:

1) **nvme control-plane**: suspicious NVMe admin/io IOCTL activity against `/dev/nvme*` (firmware download/activate, format/sanitize, namespace ops, resets—anything “this can brick or persist”)

2) **boot-plane**: suspicious writes/renames/unlinks to boot-critical artifacts and partitions (ESP/UEFI loader paths, `/boot`, initramfs, kernel images, grub configs, and raw block writes to nvme partitions containing ESP or `/boot`)

deliver as an agent-executable repo: eBPF programs + a userspace daemon + rules engine + tests + packaging.

---

## 1) non-goals (to prevent scope creep)

- no attempt to introspect NVMe firmware contents or controller flash directly
- no full-blown EDR (endpoint detection and response) suite; only NVMe/boot persistence surface area
- no kernel patching; eBPF only
- enforcement is **optional** and must be runtime-toggleable; detection must stand alone

---

## implementation status

- scaffolded repo layout per spec
- event schema types and JSONL output plumbing implemented in userspace (no BPF yet)
- config parser and minimal CLI (`run`, `validate`) with safe defaults
- rules schema + parser stubs added; default rules file wired in config
- basic rule matching and unit tests for rules + normalization

---

## 2) target environment + constraints

### supported kernels (detection mode)
- linux kernel ≥ 5.15 recommended
- requires eBPF + BTF; CO-RE preferred

### optional enforcement modes
- **eBPF LSM** enforcement requires:
  - `CONFIG_BPF_LSM=y`
  - appropriate security settings (and privileges)
- if unavailable, operate in detect-only mode (no blocking)

### privilege model
- daemon runs as root (or CAP_BPF/CAP_SYS_ADMIN/CAP_PERFMON depending on kernel)
- include a `--dry-run` mode that logs “would block” decisions without enforcing

---

## 3) repository layout (agent should create exactly this skeleton)

nvme-guard/
  README.md
  LICENSE
  go.mod
  Makefile
  cmd/
    nvme-guard/
      main.go
  internal/
    bpf/
      loader.go
      generated/
    events/
      types.go
      normalize.go
      enrich.go
      output.go
    rules/
      schema.go
      parser.go
      engine.go
      maintenance.go
    snapshot/
      baseline.go
      hasher.go
    proc/
      fds.go
      exe.go
      cgroup.go
      mountinfo.go
    metrics/
      prometheus.go
    config/
      config.go
  bpf/
    nvme_ioctl.bpf.c
    boot_vfs.bpf.c
    block_raw.bpf.c
    common.h
  configs/
    nvme-guard.example.yaml
    allowlists/
      trusted_binaries.txt
      maintenance_windows.yaml
  scripts/
    install.sh
    systemd/
      nvme-guard.service
  tests/
    rules_test.go
    normalize_test.go
    integration/
      harness.sh
      simulate_ioctl.c
      simulate_boot_write.sh
  docs/
    threat_model.md
    event_schema.md
    design_notes.md


---

## 4) build toolchain choices (explicit, agent-friendly)

### language & libraries
- userspace: **go**
- eBPF: **C** compiled with clang/llvm
- eBPF loader: `github.com/cilium/ebpf` + `bpf2go` for build reproducibility

### build commands (must work)
- `make build` → builds `./bin/nvme-guard`
- `make bpf` → compiles BPF objects and generates Go bindings
- `make test` → unit tests
- `make integration` → runs integration harness (best-effort; may require privileged env)

---

## 5) system overview (dataflow)

**kernel (eBPF)** emits events → ring buffer → **userspace daemon** ingests → enriches (procfs, hashes, mount mapping) → rules engine scores/decides → outputs alerts + optional enforcement decisions → metrics.

---

## 6) event schema (canonical; used across all sensors)

### 6.1 base envelope: `Event`
fields (json keys):
- `ts_ns` (uint64): kernel timestamp
- `sensor` (string): `nvme_ioctl` | `boot_vfs` | `block_raw`
- `severity` (string): `info` | `low` | `medium` | `high` | `critical`
- `action` (string): `observe` | `alert` | `block` | `would_block`
- `reason` (string): human-readable rule explanation
- `host` (string): hostname
- `kernel` (string): kernel release

### 6.2 process context: `ProcCtx`
- `pid`, `tgid`, `ppid`
- `uid`, `gid`
- `comm` (task name)
- `exe_path` (userspace-enriched)
- `exe_sha256` (userspace-enriched; cached)
- `cmdline` (userspace-enriched)
- `cgroup_id` (uint64)
- `cgroup_path` (userspace-enriched)
- `tty` (userspace-enriched; “is interactive” boolean)
- `container_hint` (bool; heuristic: cgroup path contains container runtime markers)

### 6.3 target context: `TargetCtx`
- `dev_major`, `dev_minor`
- `dev_path` (best-effort)
- `mount_point` (for file events)
- `file_path` (for file events; from bpf_d_path when possible)
- `inode` (for file events)
- `fs_type` (userspace-enriched via mountinfo)
- `nvme_ctrl` (optional)
- `nvme_nsid` (optional)

### 6.4 operation context: `OpCtx`
- for ioctls:
  - `syscall` = `ioctl`
  - `request` (uint64)
  - `arg_ptr` (uint64)
  - `ioctl_class` (enum): `nvme_admin` | `nvme_io` | `unknown`
  - `nvme_opcode` (uint8, if parsable)
  - `data_len` (uint32, if parsable)
- for vfs:
  - `op` = `write` | `rename` | `unlink` | `chmod` | `chattr` (if captured)
  - `bytes` (write size if available)
  - `flags` (open flags if captured)
- for block:
  - `op` = `read` | `write` | `flush` | `discard`
  - `sector`, `nr_sectors` (if available)
  - `partno` (best-effort)

**note:** kernel-side struct must be fixed-size; variable strings are truncated (e.g., 256 bytes) and nul-terminated.

---

## 7) sensors: attach points + emitted events

### 7.1 sensor A: `nvme_ioctl` (control-plane)

**purpose:** catch NVMe IOCTL usage on nvme char devices and fingerprint admin commands.

**attach points (MVP)**
- tracepoint: `syscalls:sys_enter_ioctl`
- tracepoint: `syscalls:sys_exit_ioctl` (optional: capture return code)

**kernel logic**
- on enter:
  - capture `pid/tgid`, `uid/gid`, `comm`
  - capture `fd`, `request`, `arg`
  - emit event if:
    - `request` matches known NVMe ioctl request ids (best-effort; allow unknown but gated by fd path resolution), OR
    - a heuristic indicates fd points to nvme char dev (userspace enrichment provides confirmation; kernel emits “candidate” then userspace filters)
- store `(tgid, fd)` in a small LRU map to rate-limit repeated spam from same fd/request combo

**userspace enrichment**
- resolve `/proc/<pid>/fd/<fd>` symlink to path
- confirm path matches `/dev/nvme*` (char device) or `/dev/ng*` if present
- optionally parse the ioctl arg struct bytes when safe/possible:
  - for `NVME_IOCTL_ADMIN_CMD`-like payload: read opcode/data_len
  - if parsing fails: keep `nvme_opcode = null`, still alert based on request + caller

**expected detection targets**
- firmware download/activate attempts
- format/sanitize / namespace modifications
- any NVMe admin opcode outside maintenance windows
- any NVMe ioctl from unexpected binaries (not `nvme`, not vendor tools, not known storage agents)

---

### 7.2 sensor B: `boot_vfs` (boot-plane file-level)

**purpose:** detect modifications to boot-critical files.

**attach points (preferred; uses file struct for path)**
- kprobe or fentry (CO-RE): `vfs_write`
- kprobe/fentry: `vfs_unlink`
- kprobe/fentry: `vfs_rename`
- optional: kprobe/fentry: `chmod_common` / `notify_change` for permission flips
- optional: kprobe/fentry: `security_inode_setattr` (if accessible) for immutable bit detection (best-effort)

**kernel logic**
- from `struct file*` (write) or inode/path (rename/unlink):
  - use `bpf_d_path` to obtain a canonical-ish path string
  - emit events only if path prefixes match configured boot-critical prefixes:
    - `/boot`
    - `/boot/efi`
    - `/efi` (some distros)
    - `/usr/lib/modules` (optional; initramfs sources)
  - capture inode + dev major/minor where possible

**userspace enrichment**
- compute before/after hash for touched files (if readable) with a short debounce window:
  - on first write event: schedule hash in ~250ms
  - on burst: hash after quiet period (e.g., 2s) to avoid hashing mid-write
- maintain baseline snapshots in `/var/lib/nvme-guard/baseline/`

---

### 7.3 sensor C: `block_raw` (boot-plane raw block writes)

**purpose:** catch “dd to /dev/nvme0n1p1”-style persistence that bypasses file paths.

**attach points**
- tracepoint: `block:block_rq_issue`
- tracepoint: `block:block_rq_complete` (optional for latency)
- optionally: `block:block_bio_queue` if needed for more granularity

**kernel logic**
- emit for writes/flush/discard operations targeting nvme block devices
- keep it selective:
  - only emit if device major/minor maps (userspace) to nvme disks/partitions AND
  - target partition is known ESP or `/boot` backing device (computed by userspace via mountinfo)
  - OR sector range overlaps the beginning of the ESP partition (low-sector writes often signal bootkit-ish behavior)

**userspace enrichment**
- build mapping:
  - mountpoint → device major/minor → block device path
  - determine which nvme partitions back:
    - ESP mount
    - `/boot`
    - root
- classify raw write as “boot-relevant” if it targets these partitions

---

## 8) rules engine (scoring + decisions)

### 8.1 configuration file: `configs/nvme-guard.example.yaml`

top-level:
- `mode`: `detect` | `enforce` | `dry-run-enforce`
- `output`: stdout json, file, syslog, journald
- `metrics`: prometheus listen addr
- `sensors`: enable/disable each sensor
- `paths`: boot prefixes
- `allowlists`:
  - `trusted_exe_sha256`
  - `trusted_exe_paths` (bounded; no glob footguns without explicit syntax)
  - `trusted_comm`
  - `trusted_users` / `trusted_groups`
- `maintenance_windows`: time windows with timezone `America/New_York` (explicit)
- `rules`: ordered list; first-match or score-accumulate (choose one; recommended: score-accumulate)

### 8.2 rule model

each rule:
- `id` (string)
- `when` (conditions)
- `then`:
  - `severity`
  - `score_delta`
  - `action`: `alert` or `block` (block only honored in enforce modes)
  - `message_template`

condition primitives:
- process:
  - `exe_sha256_in`, `exe_path_in`, `comm_in`, `uid_in`, `cgroup_path_contains`, `is_interactive_tty`
- target:
  - `file_path_prefix`, `device_path_prefix`, `dev_major_minor_in`
- operation:
  - `sensor_is`, `ioctl_request_in`, `nvme_opcode_in`, `vfs_op_in`, `block_op_in`
- time:
  - `not_in_maintenance_window`

### 8.3 default policy (must ship)

- **critical/block (enforce mode):**
  - NVMe firmware download/activate when `not_in_maintenance_window` AND caller not allowlisted
  - NVMe format/sanitize/namespace ops under same constraints
- **high/alert:**
  - any NVMe ioctl from a container cgroup unless explicitly allowlisted
  - write/rename/unlink under `/boot` or `/boot/efi` by non-allowlisted writers
  - raw writes to ESP partition by unknown binaries
- **medium/alert:**
  - boot writes immediately following remote login (heuristic: parent chain includes sshd) — best-effort
- **low/info:**
  - known update tools writing expected boot artifacts during maintenance

---

## 9) enforcement (optional; must be safe)

### 9.1 enforcement mechanism options

**option 1 (preferred): eBPF LSM**
- hook: `security_file_ioctl` to deny dangerous nvme ioctl requests
- hook: `security_inode_rename` / `security_inode_unlink` / `security_file_permission` for boot-plane denies

**option 2 (fallback): no kernel blocking**
- only “detect + alert”; action is `would_block` in dry-run

### 9.2 safety requirements
- enforcement must be gated by:
  - `mode=enforce` or `dry-run-enforce`
  - a runtime “maintenance toggle” (state file or unix socket command)
- always log the would-be decision with rule id and explanation
- hard fail closed is forbidden: if rules fail to parse, daemon must switch to detect-only and emit a loud error

---

## 10) userspace daemon behavior

### 10.1 ingestion
- open ringbuf readers for each BPF program
- decode fixed event structs
- normalize into canonical `Event`

### 10.2 enrichment (must be cached aggressively)
- exe path via `/proc/<pid>/exe`
- cmdline via `/proc/<pid>/cmdline`
- fd path via `/proc/<pid>/fd/<fd>` (ioctl events)
- cgroup path via `/proc/<pid>/cgroup`
- mount mappings via `/proc/self/mountinfo` + `/sys/dev/block/*`

caches:
- `pid → exe_sha256` (ttl, invalidate on exec changes)
- `dev_major:dev_minor → /dev/...` resolution
- `mountpoint → dev` resolution

### 10.3 snapshotting (boot-plane)
- maintain a baseline:
  - on startup: hash known boot artifacts (configurable list + discovered common files)
  - on events: hash changed files after debounce
- store:
  - baseline hashes + timestamps
  - change history ring (bounded)
- output “diff” records for `/boot` changes: old hash, new hash

---

## 11) output + UX

### 11.1 outputs
- JSON Lines to stdout (default)
- optional: write to `/var/log/nvme-guard/events.jsonl`
- optional: syslog/journald integration
- prometheus metrics at `/metrics`

### 11.2 CLI subcommands
- `nvme-guard run --config <path>`
- `nvme-guard validate --config <path>`
- `nvme-guard status` (shows sensor loaded, mode, maintenance state)
- `nvme-guard maintenance on|off` (toggles maintenance flag)
- `nvme-guard baseline init` (initial baseline snapshot)
- `nvme-guard baseline diff` (print last N boot changes)

---

## 12) performance + correctness constraints

- target overhead: <1–2% CPU on typical servers; must include sampling knobs
- ringbuf backpressure:
  - if events drop, emit aggregated “dropped_events” metric and periodic warning
