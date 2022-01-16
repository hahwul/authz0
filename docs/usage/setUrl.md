---
title: setUrl command
layout: default
parent: Usage
nav_order: 4
---

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