package models

type Template struct {
	Name    string   `yaml:"name"`
	Roles   []Role   `yaml:"roles"`
	URLs    []URL    `yaml:"urls"`
	Asserts []Assert `yaml:"asserts"`
}
