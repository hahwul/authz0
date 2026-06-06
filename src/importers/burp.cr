require "xml"
require "base64"
require "./base"
require "../models/target_url"
require "../utils/errors"

module Authz0
  module Importers
    # Burp Suite "Save items" XML export. Each <item> carries <url>, <method>
    # and a base64 <request> blob from which we recover the request body.
    class Burp
      def parse(content : String, base_url : String) : Array(TargetURL)
        doc = XML.parse(content)
        targets = [] of TargetURL

        doc.xpath_nodes("//item").each do |item|
          url = text_of(item, "url")
          next if url.nil? || url.empty?
          method = (text_of(item, "method") || "GET").upcase

          body : String? = nil
          if req = item.xpath_node("request")
            raw = req.content || ""
            if (req["base64"]? || "").downcase == "true"
              raw = decode_base64(raw)
            end
            body = extract_body(raw)
          end
          body = nil if body && body.empty?
          ctype = sniff_content_type(body)

          path = Importers.relativize(url, base_url)
          targets << TargetURL.new(path, method, body: body, content_type: ctype)
        end
        targets
      rescue ex : XML::Error
        raise ImportError.new("invalid Burp XML: #{ex.message}")
      end

      def from_file(path : String, base_url : String) : Array(TargetURL)
        parse(Importers.read_file(path), base_url)
      end

      private def text_of(item : XML::Node, name : String) : String?
        node = item.xpath_node(name)
        node ? node.content.strip : nil
      end

      private def decode_base64(raw : String) : String
        Base64.decode_string(raw.gsub(/\s/, ""))
      rescue
        raw
      end

      # Split a raw HTTP request into head + body and return the body. Burp
      # blobs use CRLF; tolerate bare LF too.
      private def extract_body(raw : String) : String?
        if idx = raw.index("\r\n\r\n")
          return raw[(idx + 4)..]
        end
        if idx = raw.index("\n\n")
          return raw[(idx + 2)..]
        end
        nil
      end

      private def sniff_content_type(body : String?) : String?
        return nil if body.nil? || body.empty?
        trimmed = body.lstrip
        return "json" if trimmed.starts_with?('{') || trimmed.starts_with?('[')
        return "form" if body.matches?(/\A[^=&\s]+=[^&]*(&[^=&\s]+=[^&]*)*\z/)
        nil
      end
    end
  end
end
