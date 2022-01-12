package scan

import (
	"net/http"

	"github.com/hahwul/authz0/pkg/models"
)

func checkAssert(res *http.Response, assert []models.Assert) bool {
	if res.StatusCode == 200 {
		return true
	}
	return false
}
