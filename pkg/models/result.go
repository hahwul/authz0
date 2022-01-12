package models

type Result struct {
	URL        string
	Method     string
	Assert     bool
	StatusCode int
	RespSize   int
}
