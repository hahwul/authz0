require "./base"
require "../models/target_url"
require "../utils/validator"

module Authz0
  module Importers
    # Plain URL list, one entry per line. Blank lines and `#` comments are
    # skipped. Each line is either a bare URL or "METHOD url" (e.g.
    # "POST https://api/login"). Both absolute URLs and bare paths are
    # accepted; absolute same-origin URLs are relativized against the session.
    class Urls
      def parse(content : String, base_url : String) : Array(TargetURL)
        Importers.guard_size!(content, "URL list")
        targets = [] of TargetURL
        content.each_line do |raw|
          line = raw.strip
          next if line.empty? || line.starts_with?('#')

          method = "GET"
          url = line
          parts = line.split(/\s+/, 2)
          if parts.size == 2 && Validator::KNOWN_METHODS.includes?(parts[0].upcase)
            method = parts[0].upcase
            url = parts[1].strip
          end
          next if url.empty?

          path = Importers.relativize(url, base_url)
          targets << TargetURL.new(path, method)
        end
        targets
      end

      def from_file(path : String, base_url : String) : Array(TargetURL)
        parse(Importers.read_file(path), base_url)
      end
    end
  end
end
