<h1 align="center">
  <br>
  <a href=""><img src="https://user-images.githubusercontent.com/13212227/149369752-8b344201-ebc4-43b2-8d64-b1229a5ee4c2.png" alt="" width="300px;"></a>
</h1>
<p align="center">
  <a href=""><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
  <a href="https://goreportcard.com/report/github.com/hahwul/authz0"><img src="https://goreportcard.com/badge/github.com/hahwul/authz0"></a>
  <a href="https://github.com/hahwul/authz0/actions/workflows/go.yml"><img src="https://github.com/hahwul/authz0/actions/workflows/go.yml/badge.svg"></a>
  <a href="https://twitter.com/intent/follow?screen_name=hahwul"><img src="https://img.shields.io/twitter/follow/hahwul?style=flat&logo=twitter"></a>
</p>


Authz0 is an automated authorization test tool. Unauthorized access can be identified based on URL and Role. 

URLs and Roles are managed as YAML-based templates, which can be automatically created and added through authz0. You can also test based on multiple authentication headers and cookies with a template file created/generated once.

![authz0-2](https://user-images.githubusercontent.com/13212227/149650143-a34d8826-f272-4aca-b9a7-323de268cd52.jpg)

## Usage
```
Usage:
  authz0 [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  new         Generate new template
  scan        Scanning
  setRole     Append Role to Template
  setUrl      Append URL to Template
  version     Show version

Flags:
      --debug   Print debug log
  -h, --help    help for authz0
```

## Step by Step

### Make template

```
Usage:
  authz0 new <filename> [flags]

Flags:
      --assert-fail-regex string       Set fail regex assert
      --assert-fail-size int           Set fail size assert (default -1)
      --assert-fail-status string      Set fail status assert
      --assert-success-status string   Set success status assert
  -h, --help                           help for new
      --include-roles string           Include Roles from the file
      --include-urls string            Include URLs from the file
  -n, --name string                    Template name
```

```
authz0 new admin.yaml -n test-admin --include-urls ./urls.txt --assert-fail-regex "permission denied"
```

### Modify template

Append Role to Template

```
Usage:
  authz0 setRole <filename> [flags]

Flags:
  -h, --help          help for setRole
  -n, --name string   Role name
```

```
authz0 setRole admin.yaml -n superadmin
authz0 setRole admin.yaml -n admin
authz0 setRole admin.yaml -n qa
```

Append URL to Template

```
Usage:
  authz0 setUrl <filename> [flags]

Flags:
  -a, --alias string        Alias
      --allowRole strings   Allow role names
  -d, --body string         Request Body data
      --denyRole strings    Deny role names
  -h, --help                help for setUrl
  -X, --method string       Request Method (default "GET")
  -t, --type string         Request Type [form, json] (default "form")
  -u, --url string          Request URL
```

```
authz0 setUrl admin.yaml -u https://127.0.0.1/admin -a "main page"
authz0 setUrl admin.yaml -u https://127.0.0.1/admin/api/getUser "get user"
authz0 setUrl admin.yaml -u https://127.0.0.1/admin/api/getAdmin --denyRole qa -a "get admin"
authz0 setUrl admin.yaml -u https://127.0.0.1/admin/api/getSystemKey --allowRole superadmin --denyRole admin --denyRole qa -a "get system key"
authz0 setUrl admin.yaml -u https://127.0.0.1/admin/api/updateKey -X POST -d "key=1234" -a "update key"
```

### Scan with template

```
Usage:
  authz0 scan <filename> [flags]

Flags:
      --concurrency int   Number of URLs to be test in parallel (default 1)
  -c, --cookie string     Cookie value of this test case
      --delay int         Second of Delay to HTTP Request
  -f, --format string     Result format (plain, json, markdown)
  -H, --header strings    Headers of this test case
  -h, --help              help for scan
      --no-report         Not print report (only log mode)
      --proxy string      Proxy address
  -r, --rolename string   Role name of this test case
      --timeout int       Second of Timeout to HTTP Request (default 10)
```

```
authz0 scan admin.yaml -r qa -c "auth=37F0B6E4439233442A2C1F8EC5C76E64E3B42A"
authz0 scan admin.yaml -r admin -c "auth=DF0B66038B0A4C3525CBAEF5BF732ABCAFF9EF"
authz0 scan admin.yaml -r superadmin -H "X-Admin-Key: 120439124" -H "X-API-Key: 124124"
```
