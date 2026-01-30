# nvme-guard threat model (initial)

## Goals
- Detect control-plane NVMe operations that can brick or persist (firmware, format, sanitize, namespace ops).
- Detect boot-plane persistence attempts via file writes or raw block writes.
- Provide optional enforcement with explicit operator consent.

## Assumptions
- The host may have a single NVMe root disk; accidental enforcement can be catastrophic.
- Attackers may run as root or have access to privileged utilities.
- Boot partitions and ESP are high-value targets for persistence.

## In-Scope Threats
- Unauthorized NVMe admin IOCTL usage against /dev/nvme*.
- Unauthorized writes/renames/unlinks under /boot or /boot/efi.
- Raw block writes to ESP or boot partitions.

## Out-of-Scope
- Firmware content inspection or validation.
- Full endpoint detection and response.
- Kernel patching or agent-based boot attestation.

## Expected False Positives
- Legitimate vendor storage tooling during maintenance.
- OS updates writing boot artifacts.

## Mitigations
- Allowlists for known tools and maintenance windows.
- Default detect-only mode with explicit enforcement gating.
- Safety fuse for single-NVMe-root systems.
