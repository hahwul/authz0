package set

import (
	"io/ioutil"

	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/models"
	"gopkg.in/yaml.v2"
)

func SetURL(filename string, url models.URL) error {
	var template models.Template
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {

	}
	err = yaml.Unmarshal(yamlFile, &template)
	if err != nil {
		panic(err)
	}
	template.URLs = append(template.URLs, url)
	authz0.TemplateToFile(template, filename)
	return nil
}
