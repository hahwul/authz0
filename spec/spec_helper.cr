require "spec"
require "file_utils"
require "http/server"
require "../src/authz0"

# Shared fixtures for the suite.
module SpecHelper
  extend self

  # Run a block with AUTHZ0_HOME pointed at a throwaway temp directory, so
  # store/config specs never touch the user's real ~/.authz0. The Settings
  # cache is reset on both ends so config tests see a clean slate.
  def with_temp_home(&)
    dir = File.tempname("authz0-spec")
    FileUtils.mkdir_p(dir)
    prev = ENV["AUTHZ0_HOME"]?
    ENV["AUTHZ0_HOME"] = dir
    Authz0::Settings.current = nil
    begin
      yield dir
    ensure
      prev ? (ENV["AUTHZ0_HOME"] = prev) : ENV.delete("AUTHZ0_HOME")
      Authz0::Settings.current = nil
      FileUtils.rm_rf(dir)
    end
  end

  # Spin up the access-control test target on a random port and yield its
  # base URL. Mirrors spec/support/test_server.cr (one intentional BAC bug on
  # /admin for managers, and an unprotected /secret).
  def with_test_server(&)
    # First hit on /flaky returns 503, subsequent hits 200 — for retry tests.
    flaky_hits = Atomic(Int32).new(0)
    server = HTTP::Server.new do |ctx|
      path = ctx.request.path
      if path == "/flaky"
        first = flaky_hits.add(1) == 0
        ctx.response.status_code = first ? 503 : 200
        ctx.response.print first ? "try again" : "ok"
      elsif path.starts_with?("/redirect/")
        n = path.split("/")[2]?.try(&.to_i?) || 0
        if n <= 0
          ctx.response.status_code = 200
          ctx.response.print "landed"
        else
          ctx.response.status_code = 302
          ctx.response.headers["Location"] = "/redirect/#{n - 1}"
        end
      else
        role = role_of(ctx)
        status, body = respond(ctx.request.method, path, role)
        ctx.response.status_code = status
        ctx.response.print body
      end
    end
    address = server.bind_tcp("127.0.0.1", 0)
    spawn { server.listen }
    Fiber.yield
    begin
      yield "http://127.0.0.1:#{address.port}"
    ensure
      server.close
    end
  end

  def role_of(ctx) : String
    auth = ctx.request.headers["Authorization"]?
    return "anon" if auth.nil?
    return "admin" if auth.includes?("admintoken999")
    return "manager" if auth.includes?("managertoken")
    return "user" if auth.includes?("usertoken123456")
    "anon"
  end

  def respond(method : String, path : String, role : String) : {Int32, String}
    # Echo endpoint for concurrency-integrity checks: /ep/<n> returns its own
    # path, so a worker writing to the wrong result slot becomes detectable.
    return {200, path} if path.starts_with?("/ep/")

    case {method, path}
    when {"GET", "/me"}
      {200, "hello"}
    when {"GET", "/admin"}
      (role == "admin" || role == "manager") ? {200, "admin area"} : {403, "Access Denied"}
    when {"GET", "/reports"}
      (role == "admin" || role == "manager") ? {200, "reports"} : {403, "Access Denied"}
    when {"GET", "/secret"}
      {200, "TOP SECRET"}
    when {"POST", "/login"}
      {200, "ok"}
    else
      {404, "not found"}
    end
  end
end
