package scan

import (
	"fmt"
	"sync"

	"github.com/hahwul/authz0/pkg/authz0"
	"github.com/hahwul/authz0/pkg/models"
	"github.com/hahwul/authz0/pkg/utils"
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

func Run(filename string, arguments ScanArguments) {
	template := authz0.FileToTemplate(filename)
	var results []models.Result
	var wg sync.WaitGroup
	queries := make(chan models.URL)
	for i := 0; i < arguments.Concurrency; i++ {
		wg.Add(1)
		go func() {
			for reqURL := range queries {
				res, err := sendReq(reqURL, arguments, template)
				if err != nil {

				}
				aar := false
				adr := false
				check := checkAssert(res, template.Asserts)
				if arguments.RoleName != "" {
					if check {
						if utils.ContainsFromArray(reqURL.AllowRole, arguments.RoleName) {
							aar = true
						}
					} else {
						if utils.ContainsFromArray(reqURL.DenyRole, arguments.RoleName) {
							adr = true
						}
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
					RespSize:        int(res.ContentLength),
				}
				results = append(results, result)
			}
			wg.Done()
		}()
	}

	for _, endpoint := range template.URLs {
		queries <- endpoint
	}
	close(queries)
	wg.Wait()

	fmt.Println(results)
}
