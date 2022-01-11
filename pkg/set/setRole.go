package set

import (
	"io/ioutil"

	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/models"
	"gopkg.in/yaml.v2"
)

func SetRole(filename string, role models.Role) error {
	var template models.Template
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {

	}
	err = yaml.Unmarshal(yamlFile, &template)
	if err != nil {
		panic(err)
	}
	template.Roles = append(template.Roles, role)
	authz0.TemplateToFile(template, filename)
	return nil
}
