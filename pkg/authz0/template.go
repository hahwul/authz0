package authz0

import (
	"io/ioutil"

	"github.com/hahwul/authz0/pkg/models"
	"gopkg.in/yaml.v2"
)

func TemplateToFile(template models.Template, filanem string) {
	yamlData, err := yaml.Marshal(&template)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(filanem, yamlData, 0644)
	if err != nil {
		panic(err)
	}
}

func FileToTemplate(filename string) models.Template {
	var template models.Template
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {

	}
	err = yaml.Unmarshal(yamlFile, &template)
	if err != nil {
		panic(err)
	}
	return template
}
