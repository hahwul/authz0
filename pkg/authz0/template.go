package authz0

import (
	"io/ioutil"
	"log"

	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/models"
	"gopkg.in/yaml.v2"
)

func TemplateToFile(template models.Template, filanem string) {
	yamlData, err := yaml.Marshal(&template)
	logger.GetLogger(false)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(filanem, yamlData, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func FileToTemplate(filename string) models.Template {
	var template models.Template
	logger.GetLogger(false)
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(yamlFile, &template)
	if err != nil {
		log.Fatal(err)
	}
	return template
}
