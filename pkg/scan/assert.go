package scan

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/hahwul/authz0/pkg/models"
)

func checkAssert(res *http.Response, asserts []models.Assert) bool {
	for _, assert := range asserts {
		switch assert.Type {
		case "success-status":
			vArr := strings.Split(assert.Value, ",")
			for _, v := range vArr {
				code, _ := strconv.Atoi(v)
				if res.StatusCode == code {
					return true
				}
			}

		case "fail-status":
			vArr := strings.Split(assert.Value, ",")
			for _, v := range vArr {
				code, _ := strconv.Atoi(v)
				if res.StatusCode == code {
					return false
				}
			}

		case "fail-regex":
			var reader io.ReadCloser
			switch res.Header.Get("Content-Encoding") {
			case "gzip":
				reader, _ = gzip.NewReader(res.Body)
				defer reader.Close()
			default:
				reader = res.Body
			}
			bytes, _ := ioutil.ReadAll(reader)
			str := string(bytes)
			match, _ := regexp.MatchString(str, assert.Value)
			if match {
				return false
			}
		case "fail-size":
			size, _ := strconv.Atoi(assert.Value)
			if res.ContentLength == int64(size) {
				return false
			}
		}
	}

	if res.StatusCode == 200 {
		return true
	}
	return false
}
