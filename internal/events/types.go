package events

type Sensor string

type Severity string

type Action string

type IoctlClass string

type VFSOp string

type BlockOp string

const (
	SensorNVMeIOCTL Sensor = "nvme_ioctl"
	SensorBootVFS   Sensor = "boot_vfs"
	SensorBlockRaw  Sensor = "block_raw"
)

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

const (
	ActionObserve    Action = "observe"
	ActionAlert      Action = "alert"
	ActionBlock      Action = "block"
	ActionWouldBlock Action = "would_block"
)

const (
	IoctlClassNVMeAdmin IoctlClass = "nvme_admin"
	IoctlClassNVMeIO    IoctlClass = "nvme_io"
	IoctlClassUnknown   IoctlClass = "unknown"
)

const (
	VFSWrite  VFSOp = "write"
	VFSRename VFSOp = "rename"
	VFSUnlink VFSOp = "unlink"
	VFSChmod  VFSOp = "chmod"
	VFSChattr VFSOp = "chattr"
)

const (
	BlockRead    BlockOp = "read"
	BlockWrite   BlockOp = "write"
	BlockFlush   BlockOp = "flush"
	BlockDiscard BlockOp = "discard"
)

// Event is the canonical JSON schema emitted by nvme-guard.
type Event struct {
	TSNS    uint64   `json:"ts_ns"`
	Sensor  Sensor   `json:"sensor"`
	Severity Severity `json:"severity"`
	Action   Action   `json:"action"`
	Reason   string   `json:"reason,omitempty"`
	Host     string   `json:"host,omitempty"`
	Kernel   string   `json:"kernel,omitempty"`

	Proc   ProcCtx   `json:"proc"`
	Target TargetCtx `json:"target"`
	Op     OpCtx     `json:"op"`
}

type ProcCtx struct {
	PID          int    `json:"pid"`
	TGID         int    `json:"tgid"`
	PPID         int    `json:"ppid"`
	UID          int    `json:"uid"`
	GID          int    `json:"gid"`
	Comm         string `json:"comm,omitempty"`
	ExePath      string `json:"exe_path,omitempty"`
	ExeSHA256    string `json:"exe_sha256,omitempty"`
	Cmdline      string `json:"cmdline,omitempty"`
	CgroupID     uint64 `json:"cgroup_id,omitempty"`
	CgroupPath   string `json:"cgroup_path,omitempty"`
	TTY          bool   `json:"tty,omitempty"`
	ContainerHint bool  `json:"container_hint,omitempty"`
}

type TargetCtx struct {
	DevMajor  uint32 `json:"dev_major,omitempty"`
	DevMinor  uint32 `json:"dev_minor,omitempty"`
	DevPath   string `json:"dev_path,omitempty"`
	MountPoint string `json:"mount_point,omitempty"`
	FilePath  string `json:"file_path,omitempty"`
	Inode     uint64 `json:"inode,omitempty"`
	FSType    string `json:"fs_type,omitempty"`
	NVMeCtrl  string `json:"nvme_ctrl,omitempty"`
	NVMENSID  uint32 `json:"nvme_nsid,omitempty"`
}

type OpCtx struct {
	// ioctl
	Syscall    string     `json:"syscall,omitempty"`
	Request    uint64     `json:"request,omitempty"`
	ArgPtr     uint64     `json:"arg_ptr,omitempty"`
	IoctlClass IoctlClass `json:"ioctl_class,omitempty"`
	NVMeOpcode uint8      `json:"nvme_opcode,omitempty"`
	DataLen    uint32     `json:"data_len,omitempty"`

	// vfs
	VFSOp  VFSOp  `json:"vfs_op,omitempty"`
	Bytes  uint64 `json:"bytes,omitempty"`
	Flags  uint32 `json:"flags,omitempty"`

	// block
	BlockOp   BlockOp `json:"block_op,omitempty"`
	Sector    uint64  `json:"sector,omitempty"`
	NrSectors uint32  `json:"nr_sectors,omitempty"`
	Partno    uint32  `json:"partno,omitempty"`
}
