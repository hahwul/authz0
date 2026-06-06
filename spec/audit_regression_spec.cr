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
end
