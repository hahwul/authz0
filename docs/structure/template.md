---
title: Template
layout: default
parent: Structure
nav_order: 1
---

## Template (YAML)

```yaml
name: template name
roles: # roles of this template
- name: role-name1
- name: role-name2
- name: role-name3
urls:
- url: https://authz0.hahwul.com/your-url
  method: GET # Method
  contentType: "" # or json
  body: "" # HTTP Request Body
  allowRole: # Allowed role
  - role-name1  
  - role-name2
  denyRole: [] # Denied role
  alias: "main" # Alias of this URL
asserts: # assertions
- type: success-status
  value: "200,201,202,204"
```