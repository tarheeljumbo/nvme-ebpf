package rules

import "nvme-guard/internal/events"

// RuleSet holds an ordered list of rules.
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID   string    `yaml:"id"`
	When Condition `yaml:"when"`
	Then Action    `yaml:"then"`
}

type Condition struct {
	SensorIs         []events.Sensor `yaml:"sensor_is"`
	IoctlRequestIn   []uint64        `yaml:"ioctl_request_in"`
	NVMeOpcodeIn     []uint8         `yaml:"nvme_opcode_in"`
	VFSOpIn          []events.VFSOp  `yaml:"vfs_op_in"`
	BlockOpIn        []events.BlockOp `yaml:"block_op_in"`
	FilePathPrefix   []string        `yaml:"file_path_prefix"`
	DevicePathPrefix []string        `yaml:"device_path_prefix"`
	UIDIn            []int           `yaml:"uid_in"`
	CommIn           []string        `yaml:"comm_in"`
	ExePathIn        []string        `yaml:"exe_path_in"`
	ExeSHA256In      []string        `yaml:"exe_sha256_in"`
	CgroupPathContains []string      `yaml:"cgroup_path_contains"`
	IsInteractiveTTY *bool           `yaml:"is_interactive_tty"`
	NotInMaintenanceWindow bool      `yaml:"not_in_maintenance_window"`
}

type Action struct {
	Severity     events.Severity `yaml:"severity"`
	ScoreDelta   int             `yaml:"score_delta"`
	Action       events.Action   `yaml:"action"`
	MessageTmpl  string          `yaml:"message_template"`
}
