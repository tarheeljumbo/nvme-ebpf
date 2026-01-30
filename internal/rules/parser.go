package rules

import (
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RuleSet{}, err
	}
	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return RuleSet{}, err
	}
	return rs, nil
}
