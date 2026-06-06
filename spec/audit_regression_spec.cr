require "./spec_helper"

# Regression coverage for the audit fix waves. Each test pins a specific
# confirmed finding so it can't silently come back.
describe "audit regressions" do
  # ---- importers: deeply-nested document guard (HIGH #05/#16) -------------
  describe "Importers.guard_document!" do
    it "rejects a flow-style nesting bomb with a clean ImportError (no stack-overflow crash)" do
      bomb = ("{a: " * 5000) + "1" + ("}" * 5000)
      expect_raises(Authz0::ImportError, /nested too deeply/) do
        Authz0::Importers.guard_document!(bomb, "OpenAPI document")
      end
    end

    it "rejects a block-style (indentation) nesting bomb" do
      bomb = String.build do |io|
        5000.times { |i| io << (" " * i) << "k:\n" }
      end
      expect_raises(Authz0::ImportError, /nested too deeply/) do
        Authz0::Importers.guard_document!(bomb)
      end
    end

    it "rejects an oversized document" do
      huge = "a" * (Authz0::Importers::MAX_DOCUMENT_BYTES + 1)
      expect_raises(Authz0::ImportError, /too large/) do
        Authz0::Importers.guard_document!(huge)
      end
    end

    it "passes a normal document through" do
      Authz0::Importers.guard_document!("openapi: 3.0.0\npaths:\n  /x: {get: {}}\n")
    end
  end

  # ---- archive ordering by mtime (HIGH #00/#37) --------------------------
  it "orders archived results chronologically even when same-ms names sort wrong" do
    SpecHelper.with_temp_home do
      session = Authz0::Store::SessionStore.create("ord", "https://x.test")
      FileUtils.mkdir_p(session.results_dir)
      ts = "20250101T000000000000000Z"
      older = File.join(session.results_dir, "#{ts}.json")   # base name (sorts AFTER '-1')
      newer = File.join(session.results_dir, "#{ts}-1.json") # collision suffix, written later
      File.write(older, %({"summary":{"unauthorized":0}}))
      File.write(newer, %({"summary":{"unauthorized":3}}))
      # Make the collision-suffixed file genuinely newer on disk.
      base_time = Time.utc(2025, 1, 1)
      File.utime(base_time, base_time, older)
      File.utime(base_time + 5.seconds, base_time + 5.seconds, newer)

      session.latest_result_file.should eq(newer)
      session.result_files.last.should eq(newer) # oldest → newest
    end
  end

  # ---- all-errored scan is not a clean pass (HIGH #01) -------------------
  it "marks an all-errored result set as failed (✗), not a green ✓" do
    errored = [
      Authz0::Result.new(0, "http://x/a", "GET", "user", [] of String, ["user"],
        accessible: false, expected_access: false, status_code: 0, resp_size: 0_i64,
        verdict: "?", error: "connection failed"),
    ]
    rendered = Authz0::Report.render(errored, Authz0::Report::Format::Plain, false)
    rendered.should contain("✗")
    rendered.should_not contain("✓")
    rendered.should contain("1 error")
  end

  # ---- cross-origin redirect must NOT forward credentials (HIGH #06/#07) --
  it "strips credentials on a cross-origin redirect but keeps them same-origin" do
    cross_origin_auth = nil.as(String?)
    same_origin_auth = nil.as(String?)
    cross_hit = Channel(Nil).new

    # Sink server (a different origin) records whatever Authorization it sees.
    sink = HTTP::Server.new do |ctx|
      cross_origin_auth = ctx.request.headers["Authorization"]?
      ctx.response.status_code = 200
      ctx.response.print "sink"
      cross_hit.send(nil)
    end
    sink_addr = sink.bind_tcp("127.0.0.1", 0)
    spawn { sink.listen }
    Fiber.yield

    # Target server: /cross 302s to the sink (cross-origin); /same 302s to
    # /landing (same-origin) which records the Authorization it received.
    target = HTTP::Server.new do |ctx|
      case ctx.request.path
      when "/cross"
        ctx.response.status_code = 302
        ctx.response.headers["Location"] = "http://127.0.0.1:#{sink_addr.port}/sink"
      when "/same"
        ctx.response.status_code = 302
        ctx.response.headers["Location"] = "/landing"
      when "/landing"
        same_origin_auth = ctx.request.headers["Authorization"]?
        ctx.response.status_code = 200
        ctx.response.print "landed"
      else
        ctx.response.status_code = 404
      end
    end
    target_addr = target.bind_tcp("127.0.0.1", 0)
    spawn { target.listen }
    Fiber.yield

    begin
      client = Authz0::Scan::HttpClient.new(follow_redirects: 3)
      sensitive = Set{"authorization"}

      h1 = HTTP::Headers.new
      h1["Authorization"] = "Bearer SECRET"
      client.request("GET", "http://127.0.0.1:#{target_addr.port}/cross", h1, nil, sensitive)
      cross_hit.receive # ensure the sink handler ran

      h2 = HTTP::Headers.new
      h2["Authorization"] = "Bearer SECRET"
      client.request("GET", "http://127.0.0.1:#{target_addr.port}/same", h2, nil, sensitive)

      cross_origin_auth.should be_nil             # credential dropped cross-origin
      same_origin_auth.should eq("Bearer SECRET") # but kept same-origin
    ensure
      sink.close
      target.close
    end
  end
end

# ---- Wave 2 (MEDIUM) ----------------------------------------------------
describe "audit regressions (wave 2)" do
  it "fully masks short secrets instead of revealing 8 of 9 chars (#29)" do
    Authz0::Masking.mask("passwd99x").should eq("*********")     # 9 chars → all stars
    Authz0::Masking.mask("12345678901").should eq("***********") # 11 chars → all stars
    Authz0::Masking.mask("123456789012").should eq("1234…9012")  # 12 chars → head…tail
  end

  it "keeps backslashes inside double-quoted curl args (#28)" do
    parsed = Authz0::CurlParser.parse(%q{curl -H "X-Win: C:\Users\me" https://x})
    parsed.headers["X-Win"].should eq("C:\\Users\\me")
  end

  it "defangs CSV formula injection (#18)" do
    res = [Authz0::Result.new(0, "=2+5", "GET", "@SUM(1)", [] of String, [] of String,
      accessible: true, expected_access: true, status_code: 200, resp_size: 0_i64, verdict: "O")]
    rendered = Authz0::Report.render(res, Authz0::Report::Format::Csv, false)
    rows = CSV.parse(rendered)
    rows[1][3].should eq("'=2+5")    # url cell neutralized
    rows[1][4].should eq("'@SUM(1)") # role cell neutralized
  end

  it "flattens embedded newlines in table cells so a row can't be forged (#30/#56)" do
    evil = [Authz0::Result.new(0, "http://x/a\n| 200 | GET | /admin | admin | yes |", "GET",
      "user", [] of String, [] of String,
      accessible: true, expected_access: true, status_code: 200, resp_size: 0_i64, verdict: "O")]
    md = Authz0::Report.render(evil, Authz0::Report::Format::Markdown, false)
    # The url cell must not introduce a second physical line inside the table.
    md.lines.count { |l| l.starts_with?("|") && l.includes?("/admin") }.should eq(1)
  end

  it "honors a persisted color setting but lets CLI/NO_COLOR win (#09)" do
    # nil setting is a no-op (auto).
    Authz0::Logger.apply_color_setting(nil)
    # With NO_COLOR set, a config color=true must not force color on.
    prev = ENV["NO_COLOR"]?
    ENV["NO_COLOR"] = "1"
    Authz0::Logger.apply_color_setting(true)
    Authz0::Logger.color_enabled?.should be_false
  ensure
    prev ? (ENV["NO_COLOR"] = prev) : ENV.delete("NO_COLOR")
  end
end

# ---- Wave 3 (LOW) -------------------------------------------------------
describe "audit regressions (wave 3)" do
  it "centers :center columns in markdown instead of left-aligning (#54)" do
    t = Authz0::Table.new(["A", "B"])
    t.align([:left, :center])
    t.add(["x", "y"])
    md = t.render(Authz0::Table::Style::Markdown)
    md.should contain(":-")         # center separator carries a leading colon
    md.lines[1].should contain(":") # the separator row has a center marker
  end

  it "matches a multi-value header per value, not across the join seam (#46)" do
    # Two values joined; a needle that straddles the seam must NOT match.
    resp = Authz0::Scan::HttpResponse.new(200, "ok", 2_i64,
      headers: {"set-cookie" => "a=1\nb=2"})
    straddle = [Authz0::Assertion.new("success-header", "Set-Cookie: 1\nb")]
    real = [Authz0::Assertion.new("success-header", "Set-Cookie: b=2")]
    Authz0::Scan::Asserter.accessible?(resp, straddle).should be_false
    Authz0::Scan::Asserter.accessible?(resp, real).should be_true
  end
end

# ---- continuation rounds ------------------------------------------------
describe "audit regressions (rounds)" do
  it "lengthens a short id only on a genuine collision, keeping it stable otherwise (#53)" do
    id = Authz0::ShortId.for("GET", "/a", "")
    id.size.should eq(Authz0::ShortId::LENGTH)
    # No collision → same 8-char id.
    Authz0::ShortId.unique("GET", "/a", "", taken: Set(String).new).should eq(id)
    # Collision with a different endpoint already holding that id → longer id,
    # never a silent reuse of the taken one.
    longer = Authz0::ShortId.unique("GET", "/a", "", taken: Set{id})
    longer.size.should be > Authz0::ShortId::LENGTH
    longer.should_not eq(id)
    longer.starts_with?(id).should be_true # still a prefix of the full hash
  end

  it "strips userinfo from the plain-HTTP proxy request line (#22)" do
    req_line = nil.as(String?)
    done = Channel(Nil).new
    proxy = TCPServer.new("127.0.0.1", 0)
    port = proxy.local_address.port
    spawn do
      sock = proxy.accept
      head = String.build do |io|
        while (line = sock.gets) && !line.strip.empty?
          io << line << "\n"
        end
      end
      req_line = head.lines.first?
      sock << "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
      sock.flush
      sock.close
      done.send(nil)
    end
    Fiber.yield

    client = Authz0::Scan::HttpClient.new(proxy: "http://127.0.0.1:#{port}")
    client.request("GET", "http://user:s3cret@example.test/path", HTTP::Headers.new, nil)
    done.receive
    proxy.close

    line = req_line.not_nil!
    line.should contain("http://example.test/path") # absolute-form target
    line.should_not contain("s3cret")               # userinfo removed
    line.should_not contain("user:")
  end

  it "rejects non-UTF-8 import input with a clean error instead of crashing" do
    binary = String.new(Bytes[0xff, 0xfe, 0x00, 0x01])
    expect_raises(Authz0::ImportError, /UTF-8/) do
      Authz0::Importers.ensure_utf8!(binary, "x.bin")
    end
    Authz0::Importers.ensure_utf8!("openapi: 3.0.0") # valid text passes
  end

  it "precompiles fail-regex patterns and still falls back to substring for invalid ones (perf)" do
    asserts = [
      Authz0::Assertion.new("fail-regex", "Denied"),     # valid
      Authz0::Assertion.new("fail-regex", "[unclosed("), # invalid regex
    ]
    cache = Authz0::Scan::Asserter.compile_regexes(asserts)
    cache.has_key?("Denied").should be_true      # valid → precompiled
    cache.has_key?("[unclosed(").should be_false # invalid → not cached

    # Cached path: a body matching the valid regex is judged NOT accessible.
    hit = Authz0::Scan::HttpResponse.new(200, "Access Denied", 13_i64)
    Authz0::Scan::Asserter.accessible?(hit, asserts, cache).should be_false
    # Invalid pattern still matches as a literal substring (fallback intact).
    lit = Authz0::Scan::HttpResponse.new(200, "x [unclosed( y", 14_i64)
    Authz0::Scan::Asserter.accessible?(lit, asserts, cache).should be_false
    # Clean body: no fail signal → 2xx default applies.
    ok = Authz0::Scan::HttpResponse.new(200, "all good", 8_i64)
    Authz0::Scan::Asserter.accessible?(ok, asserts, cache).should be_true
    # Same verdicts without a cache (standalone behavior unchanged).
    Authz0::Scan::Asserter.accessible?(hit, asserts).should be_false
    Authz0::Scan::Asserter.accessible?(ok, asserts).should be_true
  end
end

# ---- CLI-level regressions (drive the real binary) ----------------------
describe "audit regressions (CLI)" do
  it "exits non-zero when every probe errors (no false 'clean' pass)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "dead", "--base-url", "http://127.0.0.1:1"], home)
      CLISpec.run(["url", "add", "dead", "/x", "--deny-role", "guest"], home)
      CLISpec.run(["cred", "add", "dead", "guest", "--header", "X: Y"], home)
      r = CLISpec.run(["scan", "dead", "--no-progress", "-q", "-o", "plain"], home)
      r.status.should_not eq(0)
      r.stderr.should contain("reached no targets")
    end
  end

  it "refuses a url update that would duplicate another endpoint (no silent data loss)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["url", "add", "s", "/a"], home)
      CLISpec.run(["url", "add", "s", "/b"], home)
      dup = CLISpec.run(["url", "update", "s", "1", "--path", "/a"], home)
      dup.status.should eq(4) # ConflictError
      # both endpoints survive
      CLISpec.run(["url", "list", "s"], home).stdout.lines.size.should eq(2)
    end
  end

  it "reports a stable full-list index in a filtered url list" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["url", "add", "s", "/public"], home)                         # #0
      CLISpec.run(["url", "add", "s", "/admin", "--allow-role", "admin"], home) # #1
      out = CLISpec.run(["url", "list", "s", "--role", "admin"], home).stdout
      # The admin endpoint must list as #1 (its index in the full list), not #0.
      out.should contain("#1")
      out.should_not contain("#0")
    end
  end

  it "turns a malformed remove glob into a validation error, not a crash (#12)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["url", "add", "s", "/a[b"], home)
      r = CLISpec.run(["url", "remove", "s", "/a[b*"], home)
      r.status.should eq(2) # ValidationError, not 70 (internal error)
      r.stderr.should contain("invalid glob")
    end
  end

  it "leaves no half-created session when an import bundle has the wrong shape (#11)" do
    SpecHelper.with_temp_home do |home|
      bundle = File.tempname("bundle") + ".json"
      File.write(bundle, %({"name":"imp","base_url":"https://x","urls":[{"method":"GET"}],"creds":[],"asserts":[]}))
      begin
        r = CLISpec.run(["session", "import", bundle], home)
        r.status.should_not eq(0)
        CLISpec.run(["session", "list", "--json"], home).stdout.should contain("[]")
      ensure
        File.delete(bundle) if File.exists?(bundle)
      end
    end
  end

  it "fails doctor when a session.json is corrupt instead of hiding it (#10)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "ok", "--base-url", "https://x.test"], home)
      broken = File.join(home, "sessions", "broken")
      FileUtils.mkdir_p(broken)
      File.write(File.join(broken, "session.json"), "not json{{{")
      File.write(File.join(broken, "urls.json"), "[]")
      r = CLISpec.run(["doctor"], home)
      r.status.should eq(1)
      r.stdout.should contain("broken")
    end
  end

  it "validates --content-type instead of silently sending the wrong one (#40)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      bad = CLISpec.run(["url", "add", "s", "/a", "--content-type", "jsno", "--body", "{}"], home)
      bad.status.should eq(2)
      # a full MIME is normalized to the tag, not rejected
      CLISpec.run(["url", "add", "s", "/b", "--content-type", "application/json", "--body", "{}"], home).status.should eq(0)
    end
  end

  it "prints help even under -q (#42)" do
    SpecHelper.with_temp_home do |home|
      r = CLISpec.run(["help", "-q"], home)
      r.status.should eq(0)
      r.stdout.should contain("Commands:")
    end
  end

  it "removes a numeric-named assert type when it isn't a valid index (#31)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["assert", "add", "s", "--type", "200", "--value", "foo"], home)
      r = CLISpec.run(["assert", "remove", "s", "200"], home)
      r.status.should eq(0)
      CLISpec.run(["assert", "list", "s"], home).stdout.should_not contain("200")
    end
  end
end

# ---- usability round (4-agent dogfood) ----------------------------------
describe "usability regressions" do
  it "warns when scanning urls that have no allow/deny policy (no silent all-clear)" do
    SpecHelper.with_temp_home do |home|
      SpecHelper.with_test_server do |base|
        CLISpec.run(["session", "new", "s", "--base-url", base], home)
        CLISpec.run(["url", "add", "s", "/secret"], home) # no policy
        CLISpec.run(["cred", "add", "s", "u", "--header", "Authorization: Bearer usertoken123456"], home)
        r = CLISpec.run(["scan", "s", "--no-progress", "-o", "plain"], home)
        r.stderr.should contain("allow/deny policy")
      end
    end
  end

  it "warns (with did-you-mean) when a policy role has no matching credential" do
    SpecHelper.with_temp_home do |home|
      SpecHelper.with_test_server do |base|
        CLISpec.run(["session", "new", "s", "--base-url", base], home)
        CLISpec.run(["url", "add", "s", "/admin", "--allow-role", "admins"], home) # typo
        CLISpec.run(["cred", "add", "s", "admin", "--header", "Authorization: Bearer admintoken999"], home)
        r = CLISpec.run(["scan", "s", "--no-progress", "-o", "plain"], home)
        r.stderr.should contain("no matching credential")
        r.stderr.should contain("did you mean 'admin'")
      end
    end
  end

  it "recognizes 'anon' in an allow policy as the anonymous probe" do
    SpecHelper.with_temp_home do |home|
      SpecHelper.with_test_server do |base|
        CLISpec.run(["session", "new", "s", "--base-url", base], home)
        # /secret is open to everyone; declaring it anon-allowed must make the
        # anonymous probe EXPECTED (verdict O), not a finding.
        CLISpec.run(["url", "add", "s", "/secret", "--allow-role", "anon"], home)
        r = CLISpec.run(["scan", "s", "--anon", "--no-progress", "-o", "json"], home)
        doc = JSON.parse(r.stdout)
        anon = doc["results"].as_a.find!(&.["role"].as_s.empty?)
        anon["expected_access"].as_bool.should be_true
        anon["verdict"].as_s.should eq("O")
      end
    end
  end

  it "treats a bad flag as a usage error (exit 2) with a help hint" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      r = CLISpec.run(["scan", "s", "--bogus-flag"], home)
      r.status.should eq(2)
      r.stderr.should contain("--help")
    end
  end

  it "hints at a likely soft-denial (200 'access denied') false positive" do
    SpecHelper.with_temp_home do |home|
      SpecHelper.with_test_server do |base|
        CLISpec.run(["session", "new", "s", "--base-url", base], home)
        CLISpec.run(["url", "add", "s", "/softdeny", "--allow-role", "admin"], home)
        CLISpec.run(["cred", "add", "s", "admin", "--header", "Authorization: Bearer admintoken999"], home)
        # this role's token isn't recognized → server returns the small 200 "Access Denied"
        CLISpec.run(["cred", "add", "s", "guest", "--header", "Authorization: Bearer none"], home)
        r = CLISpec.run(["scan", "s", "--no-progress", "-o", "plain"], home)
        r.stderr.should contain("soft deni") # advisory naming the suspicious finding
      end
    end
  end

  it "reports the full scan scope in a filtered view's footer, not just shown rows" do
    full = [
      Authz0::Result.new(0, "http://x/a", "GET", "u", [] of String, ["u"],
        accessible: true, expected_access: false, status_code: 200, resp_size: 0_i64, verdict: "X"),
      Authz0::Result.new(1, "http://x/b", "GET", "u", [] of String, [] of String,
        accessible: true, expected_access: true, status_code: 200, resp_size: 0_i64, verdict: "O"),
      Authz0::Result.new(2, "http://x/c", "GET", "u", [] of String, [] of String,
        accessible: true, expected_access: true, status_code: 200, resp_size: 0_i64, verdict: "O"),
    ]
    shown = [full[0]] # e.g. --only-findings
    scope = Authz0::Report::Summary.new(full)
    out = Authz0::Report.render(shown, Authz0::Report::Format::Plain, false, scope: scope)
    out.should contain("3 targets") # true scope, not "1 target"
    out.should contain("3 probes")  # not "1 probe"
    out.should contain("showing 1") # but flags that only 1 row is displayed
  end

  it "warns that a repeated -r/--role keeps only the last (no silent multi-role)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["url", "add", "s", "/a", "--deny-role", "guest"], home)
      r = CLISpec.run(["scan", "s", "-r", "admin", "-H", "A: 1", "-r", "guest", "-H", "B: 2", "--dry-run"], home)
      r.stderr.should contain("multiple -r")
      single = CLISpec.run(["scan", "s", "-r", "admin", "-H", "A: 1", "--dry-run"], home)
      single.stderr.should_not contain("multiple -r")
    end
  end

  it "masks the proxy password in `config list` but keeps `config get` exact" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["config", "set", "proxy", "http://user:s3cretpass@127.0.0.1:8080"], home)
      list = CLISpec.run(["config", "list"], home).stdout
      list.should_not contain("s3cretpass") # overview must not leak the password
      list.should contain("user:")          # username stays for identification
      # `config get` is the scriptable accessor → exact value
      CLISpec.run(["config", "get", "proxy"], home).stdout.should contain("s3cretpass")
    end
  end

  it "inspects a single credential with `cred show` (masked, reveal, json)" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["cred", "add", "s", "admin", "--header", "Authorization: Bearer SUPERSECRETTOKEN"], home)
      CLISpec.run(["cred", "add", "s", "guest", "--header", "X-Other: someothervalue"], home)

      masked = CLISpec.run(["cred", "show", "s", "admin"], home)
      masked.status.should eq(0)
      masked.stdout.should contain("admin")
      masked.stdout.should_not contain("SUPERSECRETTOKEN") # masked by default
      masked.stdout.should_not contain("guest")            # only the asked-for role

      CLISpec.run(["cred", "show", "s", "admin", "--reveal"], home).stdout.should contain("SUPERSECRETTOKEN")
      masked_json = JSON.parse(CLISpec.run(["cred", "show", "s", "admin", "--json"], home).stdout)
      masked_json["role"].as_s.should eq("admin")
      masked_json["redacted"].as_bool.should be_true # machine consumer can tell values are masked
      revealed_json = JSON.parse(CLISpec.run(["cred", "show", "s", "admin", "--json", "--reveal"], home).stdout)
      revealed_json["redacted"].as_bool.should be_false
      CLISpec.run(["cred", "show", "s", "nobody"], home).status.should eq(3) # NotFound
    end
  end

  it "removes a url by its exact path, not only by id/glob" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["url", "add", "s", "/reports"], home)
      CLISpec.run(["url", "add", "s", "/account"], home)
      r = CLISpec.run(["url", "remove", "s", "/reports", "-y"], home)
      r.status.should eq(0)
      list = CLISpec.run(["url", "list", "s"], home).stdout
      list.should_not contain("/reports")
      list.should contain("/account") # only the matched path was removed
    end
  end

  it "accepts delete/remove/rm interchangeably across resources" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.test"], home)
      CLISpec.run(["url", "add", "s", "/a"], home)
      CLISpec.run(["cred", "add", "s", "r", "--header", "X: Y"], home)
      id = CLISpec.run(["url", "list", "s"], home).stdout[/\[([0-9a-f]+)\]/, 1]
      CLISpec.run(["url", "delete", "s", id], home).status.should eq(0)   # url uses remove/rm
      CLISpec.run(["cred", "delete", "s", "r"], home).status.should eq(0) # cred uses remove/rm
      CLISpec.run(["session", "remove", "s"], home).status.should eq(0)   # session uses delete/rm
    end
  end
end
