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

    # Generous ceiling on an imported document — bounds memory and rejects
    # obviously-pathological input before a recursive parser sees it.
    MAX_DOCUMENT_BYTES = 25_000_000

    # Nesting beyond this is rejected. Crystal's YAML parser (libyaml-backed)
    # has no depth limit and overflows the native stack on a deeply-nested
    # document — an UNCATCHABLE abort, not a YAML::ParseException. Real specs
    # nest only a few dozen levels deep, so this is comfortably out of the way.
    MAX_NESTING_DEPTH = 400

    # Pre-flight an untrusted YAML/JSON document before handing it to a
    # recursive parser. Raises ImportError (a clean, catchable error with the
    # right exit code) when the input is too large or too deeply nested, so a
    # nesting bomb can never crash the process. Covers both flow style
    # (`{a: {a: …}}`) via bracket depth and block style via indentation depth.
    def guard_document!(content : String, what : String = "document")
      if content.bytesize > MAX_DOCUMENT_BYTES
        raise ImportError.new("#{what} is too large: #{content.bytesize} bytes (limit #{MAX_DOCUMENT_BYTES})")
      end
      depth = 0
      max_flow = 0
      content.each_char do |c|
        case c
        when '{', '[' then depth += 1; max_flow = depth if depth > max_flow
        when '}', ']' then depth -= 1 if depth > 0
        end
      end
      max_indent = 0
      content.each_line do |line|
        indent = 0
        line.each_char do |ch|
          break unless ch == ' ' || ch == '\t'
          indent += 1
        end
        max_indent = indent if indent > max_indent
      end
      if max_flow > MAX_NESTING_DEPTH || max_indent > MAX_NESTING_DEPTH
        raise ImportError.new("#{what} is nested too deeply (parser-safety limit #{MAX_NESTING_DEPTH})")
      end
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

    # Merge imported targets into a session, skipping genuine duplicates (same
    # method+path+body). Dedup is on the full request shape, NOT the truncated
    # id, so two distinct endpoints that happen to share an 8-char hash prefix
    # are both kept (the second gets a longer unique id) instead of one being
    # silently dropped. Returns {added, skipped}.
    def merge(session : Store::Session, targets : Array(TargetURL)) : {Int32, Int32}
      existing = session.urls
      shapes = existing.map { |u| shape_key(u) }.to_set
      ids = existing.map(&.id).to_set
      added = 0
      skipped = 0
      targets.each do |t|
        if shapes.includes?(shape_key(t))
          skipped += 1
        else
          t.id = ShortId.unique(t.method, t.path, t.body || "", taken: ids)
          existing << t
          shapes << shape_key(t)
          ids << t.id
          added += 1
        end
      end
      session.save_urls(existing)
      {added, skipped}
    end

    # The full request identity (method + path + body) — the same fields, in the
    # same order and separator, that ShortId hashes, so dedup is consistent with
    # id derivation.
    private def shape_key(t : TargetURL) : String
      "#{t.method} #{t.path} #{t.body}"
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
