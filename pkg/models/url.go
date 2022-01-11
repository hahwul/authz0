package models

type URL struct {
	URL       string   `yaml:"url"`
	Method    string   `yaml:"method"`
	AllowRole []string `yaml:"allowRole"`
	DenyRole  []string `yaml:"denyRole"`
}
