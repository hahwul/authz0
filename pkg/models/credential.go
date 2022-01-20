package models

type Credential struct {
	Rolename string   `yaml:"rolename"`
	Headers  []string `yaml:"headers"`
}
