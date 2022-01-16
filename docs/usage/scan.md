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