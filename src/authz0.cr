# authz0 v2 — automated authorization (access-control) testing.
#
# Layout (mirrors the conventions of the author's other Crystal tools —
# ../doma, ../noir, ../hwaro):
#   utils/      logger, config, errors, validator, masking, table, short id
#   models/     plain value types serialized to JSON on disk
#   store/      session directory persistence (~/.authz0/sessions/<name>/)
#   scan/       http client, assertion engine, concurrent scanner
#   importers/  openapi / har / burp / postman / urls → TargetURL
#   report/     table / json / markdown / sarif / html result renderers
#   export/     v1-compatible YAML template writer
#   cli/        Runner + one class per verb-noun command
#
# `require "authz0"` pulls in the whole library so the binary and the
# spec suite share a single dependency graph.

require "option_parser"
require "colorize"
require "json"
require "yaml"
require "uri"
require "http/client"
require "openssl"
require "file_utils"
require "digest/sha1"

require "./utils/errors"
require "./utils/logger"
require "./utils/version"
require "./utils/config"
require "./utils/validator"
require "./utils/short_id"
require "./utils/masking"
require "./utils/table"
require "./utils/runtime"
require "./utils/suggester"
require "./utils/curl_parser"

require "./models/session_meta"
require "./models/target_url"
require "./models/credential"
require "./models/assertion"
require "./models/result"

require "./store/session"
require "./store/session_store"

require "./scan/http_client"
require "./scan/asserter"
require "./scan/scanner"

require "./importers/base"
require "./importers/urls"
require "./importers/har"
require "./importers/burp"
require "./importers/openapi"
require "./importers/postman"
require "./importers/v1_template"

require "./report/reporter"
require "./report/table_report"
require "./report/json_report"
require "./report/markdown_report"
require "./report/sarif_report"
require "./report/html_report"
require "./report/csv_report"
require "./export/yaml_export"

require "./cli/runner"

module Authz0
end
