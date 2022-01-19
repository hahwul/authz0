package new

import (
	"strconv"

	authz0 "github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/include"
	"github.com/hahwul/authz0/pkg/logger"
	models "github.com/hahwul/authz0/pkg/models"
	utils "github.com/hahwul/authz0/pkg/utils"
)

type NewArguments struct {
	Filename             string
	Name                 string
	IncludeURLs          string
	IncludeRoles         string
	IncludeHAR           string
	AssertSuccessStatus  string
	AssertFailStatus     []int
	AssertFailRegex      string
	AssertFailSize       []int
	AssertFailSizeMargin int
}

func Generate(options NewArguments) {
	var template models.Template
	template.Name = options.Name
	log := logger.GetLogger(false)

	if options.AssertSuccessStatus != "" {
		assert := setAssert("success-status", options.AssertSuccessStatus)
		template.Asserts = append(template.Asserts, assert)
		log.Info("set assert: success-status => " + options.AssertSuccessStatus)
	}
	if len(options.AssertFailStatus) > 0 {
		for _, v := range options.AssertFailStatus {
			assert := setAssert("fail-status", strconv.Itoa(v))
			template.Asserts = append(template.Asserts, assert)
			log.Info("set assert: fail-status => " + strconv.Itoa(v))
		}
	}
	if options.AssertFailRegex != "" {
		assert := setAssert("fail-regex", options.AssertFailRegex)
		template.Asserts = append(template.Asserts, assert)
		log.Info("set assert: fail-regex => " + options.AssertFailRegex)
	}
	if options.AssertFailSizeMargin != 0 {
		assert := setAssert("fail-size-margin", strconv.Itoa(options.AssertFailSizeMargin))
		template.Asserts = append(template.Asserts, assert)
		log.Info("set assert: fail-size-margin => " + strconv.Itoa(options.AssertFailSizeMargin))
	}
	if len(options.AssertFailSize) > 0 {
		for _, v := range options.AssertFailSize {
			assert := setAssert("fail-size", strconv.Itoa(v))
			template.Asserts = append(template.Asserts, assert)
			log.Info("set assert: fail-size => " + strconv.Itoa(v))
		}
	}

	if options.IncludeURLs != "" {
		urls, err := utils.ReadLinesOrLiteral(options.IncludeURLs)
		if err != nil {

		}
		log.Info("import urls from file")
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
		log.Info("import roles from file")
		for _, line := range roles {
			role := models.Role{
				Name: line,
			}
			template.Roles = append(template.Roles, role)
		}
	}
	if options.IncludeHAR != "" {
		log.Info("import HAR file")
		harObject := include.ImportHARFormat(options.IncludeHAR)
		for _, entry := range harObject.Log.Entries {
			var turl string
			if len(entry.Request.QueryString) > 0 {
				var tquery string
				for _, query := range entry.Request.QueryString {
					tquery = tquery + query.Name + "=" + query.Value + "&"
				}
				turl = entry.Request.URL + "?" + tquery
			} else {
				turl = entry.Request.URL
			}
			var ttype string
			if entry.Request.PostData.MimeType == "application/json" {
				ttype = "json"
			}
			turl = entry.Request.URL
			url := models.URL{
				URL:         turl,
				Method:      entry.Request.Method,
				Body:        entry.Request.PostData.Text,
				ContentType: ttype,
			}
			template.URLs = append(template.URLs, url)
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
