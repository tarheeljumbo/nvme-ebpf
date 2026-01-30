package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"nvme-guard/internal/config"
	"nvme-guard/internal/events"
	"nvme-guard/internal/rules"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "run":
		runCmd(os.Args[2:])
	case "validate":
		validateCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func runCmd(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "configs/nvme-guard.example.yaml", "path to config")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	ruleSet := rules.RuleSet{}
	if cfg.Rules.Path != "" {
		rs, err := rules.Load(cfg.Rules.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rules error: %v\n", err)
			os.Exit(1)
		}
		ruleSet = rs
	}

	e := events.Event{
		TSNS:     uint64(time.Now().UnixNano()),
		Sensor:   events.SensorNVMeIOCTL,
		Severity: events.SeverityInfo,
		Action:   events.ActionObserve,
		Reason:   "sample event",
		Proc: events.ProcCtx{
			PID: os.Getpid(),
			UID: os.Getuid(),
			GID: os.Getgid(),
		},
		Target: events.TargetCtx{},
		Op:     events.OpCtx{Syscall: "ioctl"},
	}

	e = events.Normalize(e)
	decision := rules.Evaluate(ruleSet, e)
	if decision.Severity != "" {
		e.Severity = decision.Severity
	}
	if decision.Action != "" {
		e.Action = decision.Action
	}
	if decision.Reason != "" {
		e.Reason = decision.Reason
	}

	if cfg.Output.Stdout {
		out := events.NewJSONLOutput(os.Stdout)
		_ = out.WriteEvent(e)
	}
}

func validateCmd(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "configs/nvme-guard.example.yaml", "path to config")
	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if cfg.Rules.Path != "" {
		if _, err := rules.Load(cfg.Rules.Path); err != nil {
			fmt.Fprintf(os.Stderr, "rules error: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Fprintln(os.Stdout, "config ok")
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nvme-guard <run|validate> [--config <path>]")
}
