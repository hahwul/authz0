require "yaml"
require "./base"
require "../models/target_url"
require "../utils/errors"

module Authz0
  module Importers
    # OpenAPI / Swagger spec importer. Accepts both JSON and YAML (YAML is a
    # JSON superset, so a single YAML parse covers both). Emits one TargetURL
    # per path × HTTP method, prefixing the server/basePath. We never
    # fabricate request bodies, but tag JSON operations' content_type so the
    # right Content-Type is sent if a body is later added.
    class OpenAPI
      HTTP_METHODS = %w[get post put patch delete head options]

      def parse(content : String, base_url : String) : Array(TargetURL)
        Importers.guard_document!(content, "OpenAPI document")
        root = YAML.parse(content)
        root_h = root.as_h?
        raise ImportError.new("not an OpenAPI document (expected a mapping at the root)") if root_h.nil?

        paths = root["paths"]?
        paths_h = paths.try(&.as_h?)
        raise ImportError.new("OpenAPI document has no 'paths'") if paths_h.nil?

        prefix = base_prefix(root)
        targets = [] of TargetURL

        paths_h.each do |path_k, methods_v|
          path = path_k.as_s? || next
          methods_h = methods_v.as_h?
          next if methods_h.nil?

          methods_h.each do |method_k, op_v|
            method = (method_k.as_s? || "").downcase
            next unless HTTP_METHODS.includes?(method)

            full = join_paths(prefix, path)
            stored = Importers.relativize(full, base_url)
            ctype = json_operation?(op_v) ? "json" : nil
            targets << TargetURL.new(stored, method.upcase, content_type: ctype)
          end
        end
        targets
      rescue ex : YAML::ParseException
        raise ImportError.new("invalid OpenAPI document: #{ex.message}")
      end

      def from_file(path : String, base_url : String) : Array(TargetURL)
        parse(Importers.read_file(path), base_url)
      end

      # Derive the URL prefix every path hangs off of. OpenAPI 3 uses
      # servers[0].url; Swagger 2 uses schemes+host+basePath. Either may be
      # absolute or a bare path.
      private def base_prefix(root : YAML::Any) : String
        if servers = root["servers"]?.try(&.as_a?)
          if first = servers.first?
            url = first["url"]?.try(&.as_s?)
            return url if url && !url.empty?
          end
        end
        # Swagger 2.
        base_path = root["basePath"]?.try(&.as_s?) || ""
        host = root["host"]?.try(&.as_s?)
        if host && !host.empty?
          scheme = root["schemes"]?.try(&.as_a?).try(&.first?).try(&.as_s?) || "https"
          return "#{scheme}://#{host}#{base_path}"
        end
        base_path
      end

      private def join_paths(prefix : String, path : String) : String
        return path if prefix.empty?
        if prefix.ends_with?('/') && path.starts_with?('/')
          prefix + path[1..]
        elsif !prefix.ends_with?('/') && !path.starts_with?('/')
          "#{prefix}/#{path}"
        else
          prefix + path
        end
      end

      private def json_operation?(op : YAML::Any) : Bool
        # A malformed spec can have a non-mapping operation value (e.g.
        # `get: "summary"`); YAML::Any#[]? raises on a non-hash receiver.
        op_h = op.as_h?
        return false if op_h.nil?
        if rb = op_h["requestBody"]?.try(&.as_h?)
          if content = rb["content"]?.try(&.as_h?)
            return content.keys.any? { |k| (k.as_s? || "").includes?("json") }
          end
        end
        if consumes = op_h["consumes"]?.try(&.as_a?)
          return consumes.any? { |c| (c.as_s? || "").includes?("json") }
        end
        false
      end
    end
  end
end
