require "uri"
require "../models/target_url"
require "../store/session"
require "../utils/errors"

module Authz0
  module Importers
    extend self

    # Resolve an import-file path, then read it (with a clear error if it's
    # missing). Used by every file-based importer.
    def read_file(path : String) : String
      unless File.exists?(path)
        raise ImportError.new("no such file: #{path}")
      end
      if File.directory?(path)
        raise ImportError.new("expected a file, got a directory: #{path}")
      end
      File.read(path)
    end

    # Turn an absolute URL into a path relative to base_url when they share an
    # origin; otherwise keep it absolute. The result is stored as
    # TargetURL#path so same-host imports stay tidy and re-point cleanly when
    # the session base_url changes, while cross-host imports remain explicit.
    def relativize(url : String, base_url : String) : String
      url = url.strip
      u = URI.parse(url)
      return url if u.host.nil? # already a bare path
      b = URI.parse(base_url)
      # Compare origins case-insensitively on host (hosts are
      # case-insensitive) and with default ports filled in, so
      # "https://API.example.com:443/x" matches a base of
      # "https://api.example.com".
      same_origin = u.scheme == b.scheme &&
                    u.host.try(&.downcase) == b.host.try(&.downcase) &&
                    effective_port(u) == effective_port(b)
      if same_origin
        target = u.request_target
        target.empty? ? "/" : target
      else
        url
      end
    rescue
      url
    end

    # A URI's port, defaulting to the scheme's well-known port so that an
    # explicit ":443" on https compares equal to an omitted port.
    private def effective_port(uri : URI) : Int32?
      uri.port || case uri.scheme
      when "https" then 443
      when "http"  then 80
      else              nil
      end
    end

    # Merge imported targets into a session, skipping any whose id already
    # exists (same method+path+body). Returns {added, skipped}.
    def merge(session : Store::Session, targets : Array(TargetURL)) : {Int32, Int32}
      existing = session.urls
      ids = existing.map(&.id).to_set
      added = 0
      skipped = 0
      targets.each do |t|
        if ids.includes?(t.id)
          skipped += 1
        else
          existing << t
          ids << t.id
          added += 1
        end
      end
      session.save_urls(existing)
      {added, skipped}
    end

    # Classify a postData/body mime type into the TargetURL content_type tag.
    def content_type_for(mime : String?) : String?
      return nil if mime.nil?
      m = mime.downcase
      return "json" if m.includes?("json")
      return "form" if m.includes?("x-www-form-urlencoded")
      nil
    end
  end
end
