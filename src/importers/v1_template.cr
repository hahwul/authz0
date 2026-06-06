require "yaml"
require "./base"
require "../models/target_url"
require "../models/credential"
require "../models/assertion"
require "../utils/errors"
require "../utils/validator"

module Authz0
  module Importers
    # Loads an authz0 **v1** YAML template (the format the original Go tool
    # consumed) into the in-memory pieces a scan needs. v1 templates carry
    # absolute URLs, so the resulting targets store full URLs and ignore the
    # session base_url — this is what powers `authz0 scan --template <file>`
    # (turnkey CI / one-off scans) and keeps v1 users on a smooth path.
    class V1Template
      record Parsed,
        base_url : String,
        targets : Array(TargetURL),
        creds : Array(Credential),
        asserts : Array(Assertion)

      def parse(content : String) : Parsed
        doc = YAML.parse(content)
        unless doc.as_h?
          raise ImportError.new("not a v1 template (expected a YAML mapping at the root)")
        end

        targets = parse_urls(doc["urls"]?)
        creds = parse_creds(doc["credentials"]?)
        asserts = parse_asserts(doc["asserts"]?)
        base_url = derive_base_url(targets)
        Parsed.new(base_url, targets, creds, asserts)
      rescue ex : YAML::ParseException
        raise ImportError.new("invalid v1 template YAML: #{ex.message}")
      end

      def from_file(path : String) : Parsed
        parse(Importers.read_file(path))
      end

      private def parse_urls(node : YAML::Any?) : Array(TargetURL)
        arr = node.try(&.as_a?)
        return [] of TargetURL if arr.nil?
        arr.compact_map do |entry|
          h = entry.as_h?
          next nil if h.nil?
          url = entry["url"]?.try(&.as_s?)
          next nil if url.nil? || url.empty?

          method = (entry["method"]?.try(&.as_s?) || "GET").upcase
          ctype_raw = entry["contentType"]?.try(&.as_s?)
          ctype = (ctype_raw && ctype_raw.downcase == "json") ? "json" : nil
          body = entry["body"]?.try(&.as_s?)
          body = nil if body && body.empty?
          alias_label = entry["alias"]?.try(&.as_s?)
          alias_label = nil if alias_label && alias_label.empty?

          TargetURL.new(
            path: url,
            method: method,
            body: body,
            content_type: ctype,
            allow_roles: string_list(entry["allowRole"]?),
            deny_roles: string_list(entry["denyRole"]?),
            alias: alias_label,
          )
        end
      end

      private def parse_creds(node : YAML::Any?) : Array(Credential)
        arr = node.try(&.as_a?)
        return [] of Credential if arr.nil?
        arr.compact_map do |entry|
          h = entry.as_h?
          next nil if h.nil?
          role = entry["rolename"]?.try(&.as_s?) || entry["role"]?.try(&.as_s?) || ""

          headers = {} of String => String
          if hlist = entry["headers"]?.try(&.as_a?)
            hlist.each do |line|
              s = line.as_s?
              next if s.nil? || s.empty?
              # v1 stores headers as "Key: Value" strings; tolerate malformed
              # lines rather than aborting the whole template load.
              begin
                k, v = Validator.header!(s)
                headers[k] = v
              rescue Authz0::ValidationError
                Logger.debug "skipping malformed v1 header: #{s}"
              end
            end
          end
          Credential.new(role, headers: headers)
        end
      end

      private def parse_asserts(node : YAML::Any?) : Array(Assertion)
        arr = node.try(&.as_a?)
        return [] of Assertion if arr.nil?
        arr.compact_map do |entry|
          h = entry.as_h?
          next nil if h.nil?
          type = entry["type"]?.try(&.as_s?)
          value = entry["value"]?.try(&.as_s?)
          next nil if type.nil? || value.nil?
          Assertion.new(type, value)
        end
      end

      private def string_list(node : YAML::Any?) : Array(String)
        arr = node.try(&.as_a?)
        return [] of String if arr.nil?
        arr.compact_map(&.as_s?)
      end

      # The origin (scheme://host[:port]) of the first absolute target, used
      # only for the scan's status line — targets keep their full URLs.
      private def derive_base_url(targets : Array(TargetURL)) : String
        first = targets.find { |t| t.path.starts_with?("http://") || t.path.starts_with?("https://") }
        return "" if first.nil?
        uri = URI.parse(first.path)
        port = uri.port
        host = uri.host
        return "" if host.nil?
        suffix = port ? ":#{port}" : ""
        "#{uri.scheme}://#{host}#{suffix}"
      rescue
        ""
      end
    end
  end
end
