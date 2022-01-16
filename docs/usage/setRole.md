---
title: setRole command
layout: default
parent: Usage
nav_order: 3
---

```
Usage:
  authz0 setRole <filename> [flags]

Flags:
  -h, --help          help for setRole
  -n, --name string   Role name
```

```
authz0 setRole admin.yaml -n superadmin
authz0 setRole admin.yaml -n admin
authz0 setRole admin.yaml -n qa
```