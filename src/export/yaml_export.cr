require "yaml"
require "../store/session"
require "../utils/masking"
require "../utils/secure_file"

module Authz0
  module Export
    # Writes a session out as a v1-compatible YAML template — the same shape
    # authz0 v1 consumed (name / roles / urls / asserts / credentials), so v2
    # sessions can feed v1 pipelines and existing tooling. URLs are emitted
    # fully resolved against the session base_url, matching v1 semantics.
    #
    # When `v1_compatible` is false a few v2-only conveniences are added
    # (per-url tags and explicit headers). v1 (Go yaml) ignores unknown keys,
    # so even the richer form stays backward-readable.
    class YamlExport
      # `redact: true` masks credential values, producing a shareable but
      # NON-runnable template (v1 would send the masked tokens). Default is
      # false: the export is the credential-bearing artifact, like creds.json.
      def initialize(@session : Store::Session, @v1_compatible : Bool = true, @redact : Bool = false)
      end

      def render : String
        base = @session.meta.base_url
        urls = @session.urls
        creds = @session.creds
        asserts = @session.asserts

        YAML.build do |yaml|
          yaml.mapping do
            yaml.scalar "name"
            yaml.scalar @session.name

            yaml.scalar "roles"
            yaml.sequence do
              roles.each do |role|
                yaml.mapping do
                  yaml.scalar "name"
                  qstr(yaml, role)
                end
              end
            end

            yaml.scalar "urls"
            yaml.sequence do
              urls.each do |u|
                yaml.mapping do
                  yaml.scalar "url"
                  qstr(yaml, u.resolve(base))
                  yaml.scalar "method"
                  qstr(yaml, u.method)
                  yaml.scalar "contentType"
                  qstr(yaml, u.content_type || "")
                  yaml.scalar "body"
                  qstr(yaml, u.body || "")
                  yaml.scalar "allowRole"
                  yaml.sequence { u.allow_roles.each { |r| qstr(yaml, r) } }
                  yaml.scalar "denyRole"
                  yaml.sequence { u.deny_roles.each { |r| qstr(yaml, r) } }
                  yaml.scalar "alias"
                  qstr(yaml, u.alias || "")

                  unless @v1_compatible
                    yaml.scalar "tags"
                    yaml.sequence { u.tags.each { |t| qstr(yaml, t) } }
                    yaml.scalar "headers"
                    yaml.mapping { u.headers.each { |k, v| yaml.scalar k; qstr(yaml, v) } }
                  end
                end
              end
            end

            yaml.scalar "asserts"
            yaml.sequence do
              asserts.each do |a|
                yaml.mapping do
                  yaml.scalar "type"
                  qstr(yaml, a.type)
                  yaml.scalar "value"
                  qstr(yaml, a.value)
                end
              end
            end

            yaml.scalar "credentials"
            yaml.sequence do
              creds.each do |c|
                yaml.mapping do
                  yaml.scalar "rolename"
                  qstr(yaml, c.role)
                  yaml.scalar "headers"
                  yaml.sequence do
                    c.headers.each { |k, v| yaml.scalar "#{k}: #{cred_value(v)}" }
                    if ch = c.cookie_header
                      yaml.scalar "Cookie: #{cred_value(ch)}"
                    end
                  end
                end
              end
            end
          end
        end
      end

      def write(path : String)
        # A credential-bearing template must not land world-readable, matching
        # creds.json's chmod-600 treatment; a redacted/secret-free one stays a
        # normal (shareable) file.
        if carries_secrets?
          SecureFile.write_private(path, render)
        else
          File.write(path, render)
        end
      end

      # True when this export carries real secrets (so the caller can warn).
      def carries_secrets? : Bool
        !@redact && @session.creds.any? { |c| !c.headers.empty? || !c.cookies.empty? }
      end

      # Emit a user-data value as an explicitly double-quoted scalar. A bare
      # scalar like `403` / `true` / `null` round-trips back as an Int/Bool/Nil,
      # and the v1 importer's `.as_s?` then returns nil and silently DROPS the
      # field (asserts, bodies, role names, policy) — quoting keeps it a string
      # for both authz0's own re-import and the v1 (Go) consumer.
      private def qstr(yaml : YAML::Builder, value : String)
        yaml.scalar(value, style: YAML::ScalarStyle::DOUBLE_QUOTED)
      end

      private def cred_value(value : String) : String
        @redact ? Masking.mask(value) : value
      end

      # Union of every role named across url policies and credentials, sorted.
      private def roles : Array(String)
        set = Set(String).new
        @session.urls.each do |u|
          u.allow_roles.each { |r| set << r }
          u.deny_roles.each { |r| set << r }
        end
        @session.creds.each { |c| set << c.role unless c.role.empty? }
        set.to_a.sort
      end
    end
  end
end
