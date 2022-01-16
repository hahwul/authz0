package models

type Result struct {
	URL             string
	Method          string
	RoleName        string
	AllowRole       []string
	DenyRole        []string
	Assert          bool
	AssertAllowRole bool
	AssertDenyRole  bool
	StatusCode      int
	RespSize        int
	Alias           string
	Result          string
	Index           string
}
