# nvme-guard event schema (v1)

This document describes the JSON Lines schema emitted by the userspace daemon.

## Event

Top-level fields:
- ts_ns (uint64): kernel timestamp
- sensor (string): nvme_ioctl | boot_vfs | block_raw
- severity (string): info | low | medium | high | critical
- action (string): observe | alert | block | would_block
- reason (string, optional): rule explanation
- host (string, optional): hostname
- kernel (string, optional): kernel release
- proc (object): ProcCtx
- target (object): TargetCtx
- op (object): OpCtx

## ProcCtx
- pid (int)
- tgid (int)
- ppid (int)
- uid (int)
- gid (int)
- comm (string, optional)
- exe_path (string, optional)
- exe_sha256 (string, optional)
- cmdline (string, optional)
- cgroup_id (uint64, optional)
- cgroup_path (string, optional)
- tty (bool, optional)
- container_hint (bool, optional)

## TargetCtx
- dev_major (uint32, optional)
- dev_minor (uint32, optional)
- dev_path (string, optional)
- mount_point (string, optional)
- file_path (string, optional)
- inode (uint64, optional)
- fs_type (string, optional)
- nvme_ctrl (string, optional)
- nvme_nsid (uint32, optional)

## OpCtx
Ioctl fields:
- syscall (string, optional)
- request (uint64, optional)
- arg_ptr (uint64, optional)
- ioctl_class (string, optional): nvme_admin | nvme_io | unknown
- nvme_opcode (uint8, optional)
- data_len (uint32, optional)

VFS fields:
- vfs_op (string, optional): write | rename | unlink | chmod | chattr
- bytes (uint64, optional)
- flags (uint32, optional)

Block fields:
- block_op (string, optional): read | write | flush | discard
- sector (uint64, optional)
- nr_sectors (uint32, optional)
- partno (uint32, optional)
