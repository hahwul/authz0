---
title: setCred command
layout: default
parent: Usage
nav_order: 5
---

```
Usage:
  authz0 setCred <filename> [flags]

Flags:
  -H, --headers strings   Headers
  -h, --help              help for setCred
  -n, --name string       Role name
```

```
authz0 setCred samples/sample.yaml -n "User" -H "X-API-Key: 1234"
authz0 setCred samples/sample.yaml -n "Admin1" -H "X-API-Key: 5555" -H "X-Test-1234: bbbb"
```