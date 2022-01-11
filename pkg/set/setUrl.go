package set

import (
	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/models"
)

func SetURL(filename string, url models.URL) error {
	template := authz0.FileToTemplate(filename)
	template.URLs = append(template.URLs, url)
	authz0.TemplateToFile(template, filename)
	return nil
}
