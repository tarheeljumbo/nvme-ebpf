package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	ModeDetect       = "detect"
	ModeDryRunEnforce = "dry-run-enforce"
	ModeEnforce      = "enforce"
)

type Config struct {
	Mode    string       `yaml:"mode"`
	Output  OutputConfig `yaml:"output"`
	Sensors Sensors      `yaml:"sensors"`
	Paths   Paths        `yaml:"paths"`
	Safety  Safety       `yaml:"safety"`
	Rules   RulesConfig  `yaml:"rules"`
}

type OutputConfig struct {
	Stdout bool   `yaml:"stdout"`
	File   string `yaml:"file"`
}

type Sensors struct {
	NVMeIOCTL bool `yaml:"nvme_ioctl"`
	BootVFS   bool `yaml:"boot_vfs"`
	BlockRaw  bool `yaml:"block_raw"`
}

type Paths struct {
	BootPrefixes []string `yaml:"boot_prefixes"`
}

type Safety struct {
	AllowEnforceOnSingleNVMERoot bool `yaml:"allow_enforce_on_single_nvme_root"`
}

type RulesConfig struct {
	Path string `yaml:"path"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	applyDefaults(&cfg)
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Mode == "" {
		cfg.Mode = ModeDetect
	}
	if cfg.Output == (OutputConfig{}) {
		cfg.Output.Stdout = true
	}
}

func validate(cfg Config) error {
	switch cfg.Mode {
	case ModeDetect, ModeDryRunEnforce, ModeEnforce:
		return nil
	case "":
		return errors.New("mode must not be empty")
	default:
		return fmt.Errorf("invalid mode: %s", cfg.Mode)
	}
}
