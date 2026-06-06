require "./spec_helper"

private def admin_cred
  Authz0::Credential.new("admin", headers: {"Authorization" => "Bearer admintoken999"})
end

private def manager_cred
  Authz0::Credential.new("manager", headers: {"Authorization" => "Bearer managertoken"})
end

private def user_cred
  Authz0::Credential.new("user", headers: {"Authorization" => "Bearer usertoken123456"})
end

private def success_asserts
  [Authz0::Assertion.new("success-status", "200,201"), Authz0::Assertion.new("fail-status", "403")]
end

describe Authz0::Scan::Scanner do
  it "detects exactly the intentional broken-access-control findings" do
    SpecHelper.with_test_server do |base|
      targets = [
        Authz0::TargetURL.new("/me", "GET"),                            # public
        Authz0::TargetURL.new("/admin", "GET", allow_roles: ["admin"]), # manager leak
        Authz0::TargetURL.new("/reports", "GET", allow_roles: ["admin", "manager"]),
        Authz0::TargetURL.new("/secret", "GET", allow_roles: ["admin"]), # open to all
      ]
      creds = [admin_cred, manager_cred, user_cred]
      scanner = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(concurrency: 4, timeout: 5, progress: false))
      results = scanner.run(targets, creds, success_asserts, base)

      results.size.should eq(targets.size * creds.size)
      findings = results.select(&.vulnerable?)

      # manager→/admin, user→/secret, manager→/secret = 3 findings.
      findings.size.should eq(3)
      findings.map { |f| {f.url.split("/").last, f.role} }.sort!.should eq(
        [{"admin", "manager"}, {"secret", "manager"}, {"secret", "user"}].sort
      )
    end
  end

  it "flags anonymous access to a protected resource" do
    SpecHelper.with_test_server do |base|
      targets = [Authz0::TargetURL.new("/secret", "GET", allow_roles: ["admin"])]
      scanner = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5))
      # No creds → anonymous probe; /secret is open so this is a finding.
      results = scanner.run(targets, [] of Authz0::Credential, success_asserts, base)
      results.size.should eq(1)
      results.first.role.should eq("")
      results.first.vulnerable?.should be_true
    end
  end

  it "produces no findings when policy matches reality" do
    SpecHelper.with_test_server do |base|
      targets = [
        Authz0::TargetURL.new("/me", "GET"),
        Authz0::TargetURL.new("/reports", "GET", allow_roles: ["admin", "manager"]),
      ]
      scanner = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5))
      results = scanner.run(targets, [admin_cred, manager_cred], success_asserts, base)
      results.count(&.vulnerable?).should eq(0)
    end
  end

  it "follows redirects only when asked, up to the hop limit" do
    SpecHelper.with_test_server do |base|
      targets = [Authz0::TargetURL.new("/redirect/3", "GET")]
      asserts = [Authz0::Assertion.new("success-status", "200")]
      anon = [] of Authz0::Credential

      no_follow = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5))
        .run(targets, anon, asserts, base)
      no_follow.first.status_code.should eq(302)

      followed = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5, follow_redirects: 10))
        .run(targets, anon, asserts, base)
      followed.first.status_code.should eq(200)

      capped = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5, follow_redirects: 1))
        .run(targets, anon, asserts, base)
      capped.first.status_code.should eq(302) # stopped before landing
    end
  end

  it "retries transient 503s when --retries is set" do
    SpecHelper.with_test_server do |base|
      targets = [Authz0::TargetURL.new("/flaky", "GET")]
      asserts = [Authz0::Assertion.new("success-status", "200")]
      anon = [] of Authz0::Credential

      # No retries: the first 503 stands.
      once = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5))
        .run(targets, anon, asserts, base)
      once.first.status_code.should eq(503)
    end

    SpecHelper.with_test_server do |base|
      targets = [Authz0::TargetURL.new("/flaky", "GET")]
      asserts = [Authz0::Assertion.new("success-status", "200")]
      anon = [] of Authz0::Credential

      # One retry: the 503 clears to 200 on the second attempt.
      retried = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5, retries: 1))
        .run(targets, anon, asserts, base)
      retried.first.status_code.should eq(200)
    end
  end

  it "errors gracefully (no malformed request) on a hostless URL" do
    client = Authz0::Scan::HttpClient.new(timeout: 2)
    resp = client.request("GET", "https:///path", HTTP::Headers.new, nil)
    resp.ok?.should be_false
    resp.error.not_nil!.should contain("no host")
  end

  it "records a request error as verdict '?' instead of crashing" do
    targets = [Authz0::TargetURL.new("/x", "GET", allow_roles: ["admin"])]
    # Nothing is listening on this port.
    scanner = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 2))
    results = scanner.run(targets, [admin_cred], success_asserts, "http://127.0.0.1:1")
    results.size.should eq(1)
    results.first.error.should_not be_nil
    results.first.verdict.should eq("?")
  end
end
