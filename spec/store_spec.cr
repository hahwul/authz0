require "./spec_helper"

describe Authz0::Store::SessionStore do
  it "creates, opens, lists, and deletes sessions" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("demo", "https://api.example.com", "d")
      s.name.should eq("demo")
      File.exists?(s.meta_path).should be_true

      Authz0::Store::SessionStore.exists?("demo").should be_true
      Authz0::Store::SessionStore.list.map(&.name).should eq(["demo"])

      reopened = Authz0::Store::SessionStore.open("demo")
      reopened.meta.base_url.should eq("https://api.example.com")

      Authz0::Store::SessionStore.delete("demo")
      Authz0::Store::SessionStore.exists?("demo").should be_false
    end
  end

  it "rejects duplicate creation and missing opens" do
    SpecHelper.with_temp_home do
      Authz0::Store::SessionStore.create("a", "https://x.com")
      expect_raises(Authz0::ConflictError) { Authz0::Store::SessionStore.create("a", "https://x.com") }
      expect_raises(Authz0::NotFoundError) { Authz0::Store::SessionStore.open("missing") }
    end
  end

  it "persists urls, creds, and asserts" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("p", "https://x.com")
      s.save_urls([Authz0::TargetURL.new("/a", "GET", allow_roles: ["admin"])])
      s.save_creds([Authz0::Credential.new("admin", headers: {"K" => "V"})])
      s.save_asserts([Authz0::Assertion.new("success-status", "200")])

      reopened = Authz0::Store::SessionStore.open("p")
      reopened.urls.size.should eq(1)
      reopened.urls.first.allow_roles.should eq(["admin"])
      reopened.creds.first.headers.should eq({"K" => "V"})
      reopened.asserts.first.type.should eq("success-status")
    end
  end

  it "writes creds.json as 0600" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("perm", "https://x.com")
      s.save_creds([Authz0::Credential.new("u", headers: {"A" => "B"})])
      perm = File.info(s.creds_path).permissions.value & 0o777
      (perm & 0o077).should eq(0) # no group/other access
      s.creds_world_readable?.should be_false
    end
  end

  it "renames and clones, carrying data" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("src", "https://x.com")
      s.save_urls([Authz0::TargetURL.new("/a", "GET")])

      renamed = Authz0::Store::SessionStore.rename("src", "dst")
      renamed.meta.name.should eq("dst")
      Authz0::Store::SessionStore.exists?("src").should be_false

      clone = Authz0::Store::SessionStore.clone("dst", "copy")
      clone.meta.name.should eq("copy")
      clone.urls.size.should eq(1)
      Authz0::Store::SessionStore.exists?("dst").should be_true # original kept
    end
  end

  it "finds urls by id and #index" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("f", "https://x.com")
      u = Authz0::TargetURL.new("/a", "GET")
      s.save_urls([u])
      s.find_url(u.id).not_nil!.path.should eq("/a")
      s.find_url("#0").not_nil!.path.should eq("/a")
      s.find_url("nope").should be_nil
    end
  end

  it "raises a clear error on corrupt JSON" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("c", "https://x.com")
      File.write(s.urls_path, "{ not json")
      expect_raises(Authz0::Error, /corrupt urls.json/) { s.urls }
    end
  end
end
