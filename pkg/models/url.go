package models

type URL struct {
	URL         string   `yaml:"url"`
	Method      string   `yaml:"method"`
	ContentType string   `yaml:"contentType"`
	Body        string   `yaml:"body"`
	AllowRole   []string `yaml:"allowRole"`
	DenyRole    []string `yaml:"denyRole"`
	Alias       string   `yaml:"alias"`
	Index       int
}
