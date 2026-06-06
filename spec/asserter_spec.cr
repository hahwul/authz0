require "./spec_helper"

private def resp(status, body = "", size = nil)
  Authz0::Scan::HttpResponse.new(status, body, (size || body.bytesize).to_i64)
end

private def assertion(type, value)
  Authz0::Assertion.new(type, value)
end

describe Authz0::Scan::Asserter do
  it "defaults to 2xx = accessible when no asserts" do
    Authz0::Scan::Asserter.accessible?(resp(200), [] of Authz0::Assertion).should be_true
    Authz0::Scan::Asserter.accessible?(resp(403), [] of Authz0::Assertion).should be_false
    Authz0::Scan::Asserter.accessible?(resp(204), [] of Authz0::Assertion).should be_true
  end

  it "honors success-status lists" do
    asserts = [assertion("success-status", "200,201")]
    Authz0::Scan::Asserter.accessible?(resp(201), asserts).should be_true
    Authz0::Scan::Asserter.accessible?(resp(202), asserts).should be_false
  end

  it "treats fail-status as not accessible" do
    asserts = [assertion("fail-status", "403")]
    Authz0::Scan::Asserter.accessible?(resp(403), asserts).should be_false
    Authz0::Scan::Asserter.accessible?(resp(200), asserts).should be_true
  end

  it "lets a fail signal override a success status (negative wins)" do
    asserts = [assertion("success-status", "200"), assertion("fail-regex", "Access Denied")]
    soft_denied = resp(200, "Access Denied")
    Authz0::Scan::Asserter.accessible?(soft_denied, asserts).should be_false
  end

  it "matches fail-regex against the body" do
    asserts = [assertion("fail-regex", "(?i)permission")]
    Authz0::Scan::Asserter.accessible?(resp(200, "No Permission Here"), asserts).should be_false
    Authz0::Scan::Asserter.accessible?(resp(200, "welcome"), asserts).should be_true
  end

  it "falls back to substring when the regex is invalid" do
    asserts = [assertion("fail-regex", "a(b")] # invalid regex
    Authz0::Scan::Asserter.accessible?(resp(200, "xa(by"), asserts).should be_false
  end

  it "applies fail-size with a margin" do
    asserts = [assertion("fail-size", "1000"), assertion("fail-size-margin", "10")]
    Authz0::Scan::Asserter.accessible?(resp(200, "", 1005), asserts).should be_false # within margin
    Authz0::Scan::Asserter.accessible?(resp(200, "", 900), asserts).should be_true   # outside margin
  end

  it "is never accessible on a request error" do
    errored = Authz0::Scan::HttpResponse.errored("timeout")
    Authz0::Scan::Asserter.accessible?(errored, [assertion("success-status", "200")]).should be_false
  end

  it "applies response-header asserts" do
    blocked = Authz0::Scan::HttpResponse.new(200, "ok", 2_i64, headers: {"x-blocked" => "true", "x-tier" => "free"})
    # fail-header by name presence
    Authz0::Scan::Asserter.accessible?(blocked, [assertion("fail-header", "X-Blocked")]).should be_false
    # fail-header by substring (case-insensitive)
    Authz0::Scan::Asserter.accessible?(blocked, [assertion("fail-header", "X-Tier: FREE")]).should be_false
    # non-matching header → falls back to 2xx default
    Authz0::Scan::Asserter.accessible?(blocked, [assertion("fail-header", "X-Tier: paid")]).should be_true
    # success-header positive signal
    Authz0::Scan::Asserter.accessible?(blocked, [assertion("success-header", "X-Tier: free")]).should be_true
    Authz0::Scan::Asserter.accessible?(blocked, [assertion("success-header", "X-Missing")]).should be_false
  end

  it "matches status classes (2xx / 4xx / 5xx)" do
    ok = [assertion("success-status", "2xx")]
    Authz0::Scan::Asserter.accessible?(resp(204), ok).should be_true
    Authz0::Scan::Asserter.accessible?(resp(301), ok).should be_false

    deny = [assertion("fail-status", "4xx,5xx")]
    Authz0::Scan::Asserter.accessible?(resp(403), deny).should be_false
    Authz0::Scan::Asserter.accessible?(resp(503), deny).should be_false
    Authz0::Scan::Asserter.accessible?(resp(200), deny).should be_true
  end
end
