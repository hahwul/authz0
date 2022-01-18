package new

import (
	"strconv"

	authz0 "github.com/hahwul/authz0/pkg/authz0"
	models "github.com/hahwul/authz0/pkg/models"
	utils "github.com/hahwul/authz0/pkg/utils"
)

type NewArguments struct {
	Filename             string
	Name                 string
	IncludeURLs          string
	IncludeRoles         string
	AssertSuccessStatus  string
	AssertFailStatus     []int
	AssertFailRegex      string
	AssertFailSize       []int
	AssertFailSizeMargin int
}

func Generate(options NewArguments) {
	var template models.Template
	template.Name = options.Name

	if options.AssertSuccessStatus != "" {
		assert := setAssert("success-status", options.AssertSuccessStatus)
		template.Asserts = append(template.Asserts, assert)
	}
	if len(options.AssertFailStatus) > 0 {
		for _, v := range options.AssertFailStatus {
			assert := setAssert("fail-status", strconv.Itoa(v))
			template.Asserts = append(template.Asserts, assert)
		}
	}
	if options.AssertFailRegex != "" {
		assert := setAssert("fail-regex", options.AssertFailRegex)
		template.Asserts = append(template.Asserts, assert)
	}
	if options.AssertFailSizeMargin != 0 {
		assert := setAssert("fail-size-margin", strconv.Itoa(options.AssertFailSizeMargin))
		template.Asserts = append(template.Asserts, assert)
	}
	if len(options.AssertFailSize) > 0 {
		for _, v := range options.AssertFailSize {
			assert := setAssert("fail-size", strconv.Itoa(v))
			template.Asserts = append(template.Asserts, assert)
		}
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
	authz0.TemplateToFile(template, options.Filename)
}

func setAssert(t, v string) models.Assert {
	assert := models.Assert{
		Type:  t,
		Value: v,
	}
	return assert
}
