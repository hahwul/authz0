require "./spec_helper"

describe Authz0::TargetURL do
  describe "#resolve" do
    it "keeps absolute URLs as-is" do
      t = Authz0::TargetURL.new("https://other.com/x", "GET")
      t.resolve("https://api.example.com").should eq("https://other.com/x")
    end

    it "replaces the base path for absolute paths" do
      t = Authz0::TargetURL.new("/admin", "GET")
      t.resolve("https://api.example.com/v1/").should eq("https://api.example.com/admin")
    end

    it "appends relative paths onto the base path" do
      t = Authz0::TargetURL.new("admin", "GET")
      t.resolve("https://api.example.com/v1").should eq("https://api.example.com/v1/admin")
    end

    it "preserves query strings" do
      t = Authz0::TargetURL.new("/search?q=1&p=2", "GET")
      t.resolve("https://api.example.com").should eq("https://api.example.com/search?q=1&p=2")
    end

    it "carries a non-default port" do
      t = Authz0::TargetURL.new("/x", "GET")
      t.resolve("http://127.0.0.1:8080").should eq("http://127.0.0.1:8080/x")
    end
  end

  it "round-trips through JSON" do
    t = Authz0::TargetURL.new("/admin", "POST", body: "{}", content_type: "json",
      allow_roles: ["admin"], deny_roles: ["user"], headers: {"X" => "1"}, tags: ["t"], alias: "a")
    parsed = Authz0::TargetURL.from_json(t.to_json)
    parsed.id.should eq(t.id)
    parsed.allow_roles.should eq(["admin"])
    parsed.headers.should eq({"X" => "1"})
    parsed.alias.should eq("a")
  end

  it "labels with alias when present, else path" do
    Authz0::TargetURL.new("/x", "GET", alias: "nice").label.should eq("nice")
    Authz0::TargetURL.new("/x", "GET").label.should eq("/x")
  end
end

describe Authz0::Credential do
  it "renders a cookie header" do
    c = Authz0::Credential.new("user", cookies: {"a" => "1", "b" => "2"})
    c.cookie_header.should eq("a=1; b=2")
  end

  it "treats empty role as anonymous" do
    Authz0::Credential.new("").anonymous?.should be_true
    Authz0::Credential.new("").display_role.should eq("<anon>")
  end
end
