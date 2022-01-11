package new

import (
	"io/ioutil"
	"strconv"

	models "github.com/hahwul/authz0/pkg/models"
	utils "github.com/hahwul/authz0/pkg/utils"
	"gopkg.in/yaml.v2"
)

type NewArguments struct {
	Filename            string
	Name                string
	IncludeURLs         string
	IncludeRoles        string
	AssertSuccessStatus string
	AssertFailStatus    string
	AssertFailRegex     string
	AssertFailSize      int
}

func Generate(options NewArguments) {
	var template models.Template
	template.Name = options.Name

	if options.AssertSuccessStatus != "" {
		assert := setAssert("success-status", options.AssertSuccessStatus)
		template.Asserts = append(template.Asserts, assert)
	}
	if options.AssertFailStatus != "" {
		assert := setAssert("fail-status", options.AssertFailStatus)
		template.Asserts = append(template.Asserts, assert)
	}
	if options.AssertFailRegex != "" {
		assert := setAssert("fail-regex", options.AssertFailRegex)
		template.Asserts = append(template.Asserts, assert)
	}
	if options.AssertFailSize != -1 {
		assert := setAssert("fail-size", strconv.Itoa(options.AssertFailSize))
		template.Asserts = append(template.Asserts, assert)
	}

	if options.IncludeURLs != "" {
		urls, err := utils.ReadLinesOrLiteral(options.IncludeURLs)
		if err != nil {

		}
		for _, line := range urls {
			url := models.URL{
				URL: line,
			}
			template.URLs = append(template.URLs, url)
		}
	}
	if options.IncludeRoles != "" {
		roles, err := utils.ReadLinesOrLiteral(options.IncludeRoles)
		if err != nil {

		}
		for _, line := range roles {
			role := models.Role{
				Name: line,
			}
			template.Roles = append(template.Roles, role)
		}
	}
	yamlData, err := yaml.Marshal(&template)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(options.Filename, yamlData, 0644)
	if err != nil {
		panic(err)
	}
}

func setAssert(t, v string) models.Assert {
	assert := models.Assert{
		Type:  t,
		Value: v,
	}
	return assert
}
