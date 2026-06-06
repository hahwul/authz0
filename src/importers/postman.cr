require "json"
require "./base"
require "../models/target_url"
require "../utils/errors"

module Authz0
  module Importers
    # Postman collection (v2.x) importer. The collection is a tree of items;
    # leaf items carry a `request` (method, url, optional raw body). Folders
    # nest under their own `item` arrays and are walked recursively.
    class Postman
      # Collection-level {{variable}} substitutions, populated per parse.
      @vars : Hash(String, String) = {} of String => String

      def parse(content : String, base_url : String) : Array(TargetURL)
        root = JSON.parse(content)
        items = root["item"]?.try(&.as_a?)
        raise ImportError.new("not a Postman collection (no 'item' array)") if items.nil?

        @vars = collection_vars(root)
        targets = [] of TargetURL
        walk(items, base_url, targets)
        targets
      rescue ex : JSON::ParseException
        raise ImportError.new("invalid Postman JSON: #{ex.message}")
      end

      def from_file(path : String, base_url : String) : Array(TargetURL)
        parse(Importers.read_file(path), base_url)
      end

      # Build the {{key}} → value map from the collection's `variable` array.
      private def collection_vars(root : JSON::Any) : Hash(String, String)
        out = {} of String => String
        if arr = root["variable"]?.try(&.as_a?)
          arr.each do |v|
            h = v.as_h?
            next if h.nil?
            key = h["key"]?.try(&.as_s?)
            val = h["value"]?.try(&.as_s?)
            out[key] = val if key && val
          end
        end
        out
      end

      # Replace {{var}} tokens with their collection value; leave unknown ones
      # untouched (they'll be flagged as templated on import).
      private def substitute(text : String) : String
        return text if @vars.empty?
        text.gsub(/\{\{([^}]+)\}\}/) do |match|
          @vars[$1.strip]? || match
        end
      end

      private def walk(items : Array(JSON::Any), base_url : String, targets : Array(TargetURL))
        items.each do |item|
          h = item.as_h?
          next if h.nil?

          if children = item["item"]?.try(&.as_a?)
            walk(children, base_url, targets) # folder
            next
          end

          req = item["request"]?
          next if req.nil?
          target = build_target(req, base_url)
          targets << target if target
        end
      end

      private def build_target(req : JSON::Any, base_url : String) : TargetURL?
        # `request` may be a bare URL string or an object.
        if url = req.as_s?
          path = Importers.relativize(url, base_url)
          return TargetURL.new(path, "GET")
        end

        method = (req["method"]?.try(&.as_s?) || "GET").upcase
        url = extract_url(req["url"]?)
        return nil if url.nil? || url.empty?
        url = substitute(url)

        body, ctype = extract_body(req["body"]?)
        body = substitute(body) if body
        path = Importers.relativize(url, base_url)
        TargetURL.new(path, method, body: body, content_type: ctype)
      end

      # Postman url is either a string or an object with `raw` (and parts).
      private def extract_url(url : JSON::Any?) : String?
        return nil if url.nil?
        if s = url.as_s?
          return s
        end
        # Guard the hash access: a malformed collection might have `url` be a
        # number/array, and JSON::Any#[]? raises on non-hash receivers.
        if h = url.as_h?
          if raw = h["raw"]?.try(&.as_s?)
            return raw
          end
        end
        nil
      end

      private def extract_body(body : JSON::Any?) : {String?, String?}
        return {nil, nil} if body.nil?
        h = body.as_h?
        return {nil, nil} if h.nil?
        mode = body["mode"]?.try(&.as_s?)
        case mode
        when "raw"
          raw = body["raw"]?.try(&.as_s?)
          return {nil, nil} if raw.nil? || raw.empty?
          ctype = sniff(raw, body)
          {raw, ctype}
        when "urlencoded"
          pairs = body["urlencoded"]?.try(&.as_a?)
          return {nil, nil} if pairs.nil?
          encoded = pairs.compact_map do |p|
            ph = p.as_h?
            next nil if ph.nil? # skip non-object entries instead of crashing
            key = ph["key"]?.try(&.as_s?)
            val = ph["value"]?.try(&.as_s?) || ""
            key ? "#{key}=#{val}" : nil
          end.join("&")
          encoded.empty? ? {nil, nil} : {encoded, "form"}
        else
          {nil, nil}
        end
      end

      private def sniff(raw : String, body : JSON::Any) : String?
        # Honor an explicit language hint when present. Each hop is hash-guarded
        # because JSON::Any#[]? raises on non-hash receivers.
        lang = body.as_h?.try(&.["options"]?)
          .try(&.as_h?).try(&.["raw"]?)
          .try(&.as_h?).try(&.["language"]?)
          .try(&.as_s?)
        if lang && lang.downcase == "json"
          return "json"
        end
        trimmed = raw.lstrip
        return "json" if trimmed.starts_with?('{') || trimmed.starts_with?('[')
        nil
      end
    end
  end
end
