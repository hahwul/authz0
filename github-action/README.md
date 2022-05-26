# action-authz0
Authorization test on github action. Find Unauthorized access can be identified based on URLs and Roles & Credentials.

## Usage
- inputs
  - `template`: scan template code
- output
  - `output`: scan result (JSON Format) 

## Step by Step
1. Write or Generate Authz0 Template ([Spec](https://authz0.hahwul.com/structure/template.html) / [Commands](https://authz0.hahwul.com/usage/new.html))
```
authz0 new yourTemplate.yml --include-zap urls.har
authz0 setRole admin.yaml -n User
authz0 setCred yourTemplate.yml -n "User" -H "X-API-Key: 1234"
```
2. Write workflow file with template code
```
cat yourTemplate.yml
```
4. Handle `jobs.<your-job-name>.outputs.output`

## Sample workflow
```yaml
on: [push]

jobs:
  authz0_scan:
    runs-on: ubuntu-latest
    name: Scanning
    steps:
      - name: Checkout
        uses: actions/checkout@v2
        with:
          ref: main
      - name: Authz0 - Scan
        uses: hahwul/action-authz0@main
        id: authz0
        with:
          template: |
            name: sample template
            roles:
            - name: Admin1
            - name: User1
            urls:
            - url: https://www.hahwul.com
              method: GET
              contentType: ""
              body: ""
              allowRole:
              - Admin
              - Admin1
              - SuperAdmin
              - User
              denyRole: []
              alias: main
            - url: https://www.hahwul.com/about/
              method: GET
              contentType: ""
              body: ""
              allowRole:
              - Admin
              - Admin1
              - SuperAdmin
              denyRole: []
              alias: about
```