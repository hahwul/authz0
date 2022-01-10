package models

type Template struct {
	Name     string   `yaml:"name"`
	Role     []roles  `yaml:"roles"`
	URLs     []URL    `yaml:"urls"`
	Policies []Policy `yaml"policies"`
}
