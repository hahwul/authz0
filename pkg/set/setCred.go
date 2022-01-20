package set

import (
	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/models"
)

func SetCred(filename string, tCred models.Credential) error {
	template := authz0.FileToTemplate(filename)
	template.Credentials = append(template.Credentials, tCred)
	authz0.TemplateToFile(template, filename)
	return nil
}
