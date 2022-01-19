package include

import (
	"encoding/json"
	"io/ioutil"
)

type HARObject struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string      `json:"version"`
	Creator interface{} `json:"creator"`
	Entries []Entry     `json:"entries"`
}

type Entry struct {
	Request Request `json:"request"`
}

type Request struct {
	Method      string        `json:"method"`
	URL         string        `json:"url"`
	QueryString []queryString `json:"queryString"`
	PostData    PostData      `json:"postData"`
}

type queryString struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

func ImportZAPFormat(filename string) HARObject {
	var harObject HARObject
	harFile, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(harFile, &harObject)
	if err != nil {
		panic(err)
	}
	return harObject
}
