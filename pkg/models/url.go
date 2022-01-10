package models

type URL struct {
	URL       string   `yaml:"url"`
	AllowRole []string `yaml:"allowRole"`
	DenyRole  []string `yaml:"denyRole"`
}
