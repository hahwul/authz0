require "json"
require "./base"
require "../models/target_url"
require "../utils/errors"

module Authz0
  module Importers
    # HAR 1.2 archive (ZAP "Save as HAR", Chrome DevTools export, Burp HAR).
    # We only read log.entries[].request — method, url, and any postData.
    class Har
      # Minimal HAR shape. Unknown keys are ignored by JSON::Serializable;
      # everything we touch is nilable so partial archives don't crash.
      class Root
        include JSON::Serializable
        property log : Log?
      end

      class Log
        include JSON::Serializable
        property entries : Array(Entry) = [] of Entry
      end

      class Entry
        include JSON::Serializable
        property request : Request?
      end

      class Request
        include JSON::Serializable
        property method : String = "GET"
        property url : String = ""
        @[JSON::Field(key: "postData")]
        property post_data : PostData?
      end

      class PostData
        include JSON::Serializable
        @[JSON::Field(key: "mimeType")]
        property mime_type : String?
        property text : String?
      end

      def parse(content : String, base_url : String) : Array(TargetURL)
        root = Root.from_json(content)
        log = root.log
        return [] of TargetURL if log.nil?

        targets = [] of TargetURL
        log.entries.each do |entry|
          req = entry.request
          next if req.nil? || req.url.empty?

          body = req.post_data.try(&.text)
          body = nil if body && body.empty?
          ctype = Importers.content_type_for(req.post_data.try(&.mime_type))
          path = Importers.relativize(req.url, base_url)
          targets << TargetURL.new(path, req.method.upcase, body: body, content_type: ctype)
        end
        targets
      rescue ex : JSON::ParseException
        raise ImportError.new("invalid HAR JSON: #{ex.message}")
      end

      def from_file(path : String, base_url : String) : Array(TargetURL)
        parse(Importers.read_file(path), base_url)
      end
    end
  end
end
