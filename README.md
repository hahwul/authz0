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

## 🛸 Key Features
* Generate scan template `$ authz0 new`
    * Include URLs
    * Include Roles
* Easy modify scan template (Role, URL) `$ authz0 setUrl` `$ authz0 setRole`
* Scanning authorization(access-control) with template `$ authz0 scan`

## 🚀 Installation
*go install*
```
go install github.com/hahwul/authz0@latest
```

*homebrew*
```
brew tap hahwul/authz0
brew install authz0
```

Need more information? please refer to [installation guide](https://authz0.hahwul.com/installation.html)

## 📖 Documents
https://authz0.hahwul.com

## 🤔 Question
Please use [discussions](https://github.com/hahwul/authz0/discussions) actively!

## 📌 Changelog
Detailed changes for each release are documented in the [release notes](https://github.com/hahwul/authz0/releases).

## ❤️ Contributing
Authz0's open-source project and made it with ❤️
if you want contribute this project, please see [CONTRIBUTING.md](https://github.com/hahwul/authz0/blob/main/CONTRIBUTING.md) and Pull-Request with cool your contents.

[![](/CONTRIBUTORS.svg)](https://github.com/hahwul/authz0/graphs/contributors)