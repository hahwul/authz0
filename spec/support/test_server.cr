# Standalone HTTP test target for dogfooding the scanner. Models a small API
# with one INTENTIONAL broken-access-control bug so the scanner has something
# real to find.
#
#   GET  /me        → 200 for everyone (public)
#   GET  /admin     → 200 for admin AND manager (BUG: manager shouldn't), else 403
#   GET  /reports   → 200 for admin/manager, else 403
#   GET  /secret    → 200 for EVERYONE incl. anonymous (BUG: should be admin-only)
#   POST /login     → 200
#   everything else → 404
#
# Tokens: admin=admintoken999, manager=managertoken, user=usertoken123456
require "http/server"

port = (ARGV[0]? || "0").to_i

def role_of(ctx) : String
  auth = ctx.request.headers["Authorization"]?
  return "anon" if auth.nil?
  case auth
  when .includes?("admintoken999")   then "admin"
  when .includes?("managertoken")    then "manager"
  when .includes?("usertoken123456") then "user"
  else                                    "anon"
  end
end

server = HTTP::Server.new do |ctx|
  role = role_of(ctx)
  path = ctx.request.path
  method = ctx.request.method

  status, body =
    case {method, path}
    when {"GET", "/me"}
      {200, "hello"}
    when {"GET", "/admin"}
      # BUG: manager is allowed through here too.
      (role == "admin" || role == "manager") ? {200, "admin area"} : {403, "Access Denied"}
    when {"GET", "/reports"}
      (role == "admin" || role == "manager") ? {200, "reports"} : {403, "Access Denied"}
    when {"GET", "/secret"}
      # BUG: no authorization check at all.
      {200, "TOP SECRET"}
    when {"POST", "/login"}
      {200, "ok"}
    else
      {404, "not found"}
    end

  ctx.response.status_code = status
  ctx.response.print body
end

address = server.bind_tcp("127.0.0.1", port)
# Print the actual port (when 0 was requested) so the harness can read it.
STDOUT.puts address.port
STDOUT.flush
server.listen
