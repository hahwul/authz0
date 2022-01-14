package scan

import (
	"strconv"
	"sync"

	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/logger"
	"github.com/hahwul/authz0/pkg/models"
	"github.com/hahwul/authz0/pkg/utils"
	"github.com/sirupsen/logrus"
)

type ScanArguments struct {
	RoleName     string
	Cookie       string
	Headers      []string
	Concurrency  int
	Delay        int
	Timeout      int
	ProxyAddress string
}

func Run(filename string, arguments ScanArguments, debug bool) []models.Result {
	var results []models.Result
	var wg sync.WaitGroup
	log := logger.GetLogger(debug)
	queries := make(chan models.URL)
	template := authz0.FileToTemplate(filename)
	log.Info("loaded testing template: " + template.Name)
	if arguments.RoleName != "" {
		log.Info("authorization test about the '" + arguments.RoleName + "' role")
	}
	for i := 0; i < arguments.Concurrency; i++ {
		wg.Add(1)
		go func() {
			for reqURL := range queries {
				res, cl, err := sendReq(reqURL, arguments, template)
				if err != nil {
					log.Debug("sendReq Error")
					log.Trace(err)
				}
				aar := false
				adr := false
				rlt := "O"
				rltValue := true
				check := checkAssert(res, template.Asserts, cl)
				if arguments.RoleName != "" {
					if check {
						if len(reqURL.AllowRole) > 0 {
							if utils.ContainsFromArray(reqURL.AllowRole, arguments.RoleName) {
								aar = true
								rltValue = rltValue && true
							} else {
								rltValue = rltValue && false
							}
						}
						if len(reqURL.DenyRole) > 0 {
							if utils.ContainsFromArray(reqURL.DenyRole, arguments.RoleName) {
								adr = false
								rltValue = rltValue && false
							} else {
								rltValue = rltValue && true
							}
						}
					} else {
						if len(reqURL.AllowRole) > 0 {
							if utils.ContainsFromArray(reqURL.AllowRole, arguments.RoleName) {
								aar = true
								rltValue = rltValue && false
							} else {
								rltValue = rltValue && true
							}
						}
						if len(reqURL.DenyRole) > 0 {
							if utils.ContainsFromArray(reqURL.DenyRole, arguments.RoleName) {
								adr = true
								rltValue = rltValue && true
							}
						}
					}
					if !rltValue {
						rlt = "X"
					}
				}

				result := models.Result{
					URL:             reqURL.URL,
					Method:          reqURL.Method,
					RoleName:        arguments.RoleName,
					AllowRole:       reqURL.AllowRole,
					DenyRole:        reqURL.DenyRole,
					Assert:          check,
					AssertAllowRole: aar,
					AssertDenyRole:  adr,
					StatusCode:      res.StatusCode,
					RespSize:        cl,
					Alias:           reqURL.Alias,
					Result:          rlt,
				}
				results = append(results, result)
				logField := logrus.Fields{
					"status": result.StatusCode,
				}
				if arguments.RoleName != "" {
					logField["rlt"] = "role-match: " + rlt
				}
				if result.Alias != "" {
					logField["alias"] = result.Alias
				}
				if result.AssertAllowRole {
					logField["aar"] = "matched: allow"
				}
				if result.AssertDenyRole {
					logField["adr"] = "matched: deny"
				}
				if arguments.RoleName != "" {
					if rltValue {
						log.WithFields(logField).Info(result.Method + " " + result.URL)
					} else {
						log.WithFields(logField).Warn(result.Method + " " + result.URL)
					}
				} else {
					if check {
						log.WithFields(logField).Info(result.Method + " " + result.URL)
					} else {
						log.WithFields(logField).Warn(result.Method + " " + result.URL)
					}
				}
				log.WithFields(logrus.Fields{
					"status": result.StatusCode,
					"alias":  result.Alias,
					"aar":    aar,
					"adr":    adr,
					"size":   cl,
				}).Debug("")
			}
			wg.Done()
		}()
	}
	log.Info("targets:  " + strconv.Itoa(len(template.URLs)) + " URLs")
	for _, endpoint := range template.URLs {
		queries <- endpoint
	}
	close(queries)
	wg.Wait()
	return results
}
