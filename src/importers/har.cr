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
        property headers : Array(NameValue) = [] of NameValue
        @[JSON::Field(key: "postData")]
        property post_data : PostData?
      end

      class NameValue
        include JSON::Serializable
        property name : String = ""
        property value : String = ""
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

      # Auth header names worth lifting into a credential (Cookie is split out
      # into cookies; the rest stay as headers).
      AUTH_HEADERS = %w[authorization x-api-key api-key x-auth-token x-csrf-token x-xsrf-token]

      record Credentials, headers : Hash(String, String), cookies : Hash(String, String) do
        def empty? : Bool
          headers.empty? && cookies.empty?
        end
      end

      # Extract a credential from captured traffic: the auth-bearing headers
      # (and Cookie) from the first request that carries any. Predictable and
      # good enough — HAR captures usually share one identity.
      def credentials(content : String) : Credentials
        root = Root.from_json(content)
        headers = {} of String => String
        cookies = {} of String => String
        log = root.log
        return Credentials.new(headers, cookies) if log.nil?

        log.entries.each do |entry|
          req = entry.request
          next if req.nil?
          req.headers.each do |h|
            name = h.name.lstrip(':') # HTTP/2 pseudo-headers arrive as ":authority"
            lower = name.downcase
            if lower == "cookie"
              split_cookies(h.value, cookies)
            elsif AUTH_HEADERS.includes?(lower)
              headers[name] = h.value
            end
          end
          break unless headers.empty? && cookies.empty?
        end
        Credentials.new(headers, cookies)
      rescue ex : JSON::ParseException
        raise ImportError.new("invalid HAR JSON: #{ex.message}")
      end

      def credentials_from_file(path : String) : Credentials
        credentials(Importers.read_file(path))
      end

      private def split_cookies(raw : String, into : Hash(String, String))
        raw.split(';').each do |pair|
          eq = pair.index('=')
          next unless eq
          name = pair[0...eq].strip
          into[name] = pair[(eq + 1)..].strip unless name.empty?
        end
      end
    end
  end
end
