---
title: Scan command
layout: default
parent: Usage
nav_order: 2
---

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
  -o, --output string     Save result to output file
      --proxy string      Proxy address
  -r, --rolename string   Role name of this test case
      --timeout int       Second of Timeout to HTTP Request (default 10)
```

e.g
```
authz0 scan admin.yaml -r qa -c "auth=37F0B6E4439233442A2C1F8EC5C76E64E3B42A"
authz0 scan admin.yaml -r admin -c "auth=DF0B66038B0A4C3525CBAEF5BF732ABCAFF9EF"
authz0 scan admin.yaml -r superadmin -H "X-Admin-Key: 120439124" -H "X-API-Key: 124124"
```