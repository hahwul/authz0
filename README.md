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

![authz0-flow](https://user-images.githubusercontent.com/13212227/149371800-d8503685-1c38-4261-902c-81225e8bf89f.png)

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
