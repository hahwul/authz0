package scan

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hahwul/authz0/pkg/models"
)

func sendReq(req models.URL, args ScanArguments, template models.Template, headers []string) (*http.Response, int, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(args.Timeout) * time.Second,
			DualStack: true,
		}).DialContext,
	}
	if args.ProxyAddress != "" {
		proxyAddress, err := url.Parse(args.ProxyAddress)
		if err != nil {

		}
		transport.Proxy = http.ProxyURL(proxyAddress)
	}
	client := &http.Client{
		Timeout:   time.Duration(args.Timeout) * time.Second,
		Transport: transport,
	}
	var r *http.Request
	if req.Body != "" {
		r, _ = http.NewRequest(req.Method, req.URL, bytes.NewBuffer([]byte(req.Body)))
	} else {
		r, _ = http.NewRequest(req.Method, req.URL, nil)
	}
	if req.ContentType == "json" {
		r.Header.Add("Content-Type", "application/json")
	} else {
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	}

	if len(headers) > 0 {
		for _, v := range headers {
			h := strings.Split(v, ": ")
			if len(h) > 1 {
				r.Header.Add(h[0], h[1])
			}
		}
	}
	if args.Cookie != "" {
		r.Header.Add("Cookie", args.Cookie)
	}

	resp, err := client.Do(r)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	return resp, int(resp.ContentLength), nil
}
