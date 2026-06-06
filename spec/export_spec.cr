require "./spec_helper"

describe Authz0::Export::YamlExport do
  it "emits a v1-compatible template that re-parses" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("e", "https://api.example.com")
      s.save_urls([
        Authz0::TargetURL.new("/admin", "GET", allow_roles: ["admin"], deny_roles: ["user"], alias: "admin"),
        Authz0::TargetURL.new("/login", "POST", body: %({"u":1}), content_type: "json"),
      ])
      s.save_creds([Authz0::Credential.new("admin", headers: {"X-API-Key" => "secret"}, cookies: {"sid" => "1"})])
      s.save_asserts([Authz0::Assertion.new("success-status", "200,201")])

      yaml = Authz0::Export::YamlExport.new(s).render
      doc = YAML.parse(yaml)

      doc["name"].as_s.should eq("e")
      doc["roles"].as_a.map(&.["name"].as_s).should contain("admin")

      urls = doc["urls"].as_a
      urls.size.should eq(2)
      urls[0]["url"].as_s.should eq("https://api.example.com/admin")
      urls[0]["denyRole"].as_a.map(&.as_s).should eq(["user"])
      urls[1]["contentType"].as_s.should eq("json")
      urls[1]["body"].as_s.should eq(%({"u":1}))

      creds = doc["credentials"].as_a
      creds[0]["rolename"].as_s.should eq("admin")
      headers = creds[0]["headers"].as_a.map(&.as_s)
      headers.should contain("X-API-Key: secret")
      headers.any?(&.starts_with?("Cookie: sid=1")).should be_true
    end
  end
end
