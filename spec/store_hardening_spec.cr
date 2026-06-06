require "./spec_helper"

# Quality round: the session store must survive corrupt/odd on-disk state with
# clean errors, and keep credential files private through clone.
describe "store hardening" do
  it "raises a clear error opening a session with corrupt session.json" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("c", "https://x.com")
      File.write(s.meta_path, "{ not json")
      expect_raises(Authz0::Error, /corrupt session.json/) { Authz0::Store::SessionStore.open("c") }
    end
  end

  it "raises a clear error on corrupt creds.json access" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("c", "https://x.com")
      File.write(s.creds_path, "{ not an array")
      reopened = Authz0::Store::SessionStore.open("c")
      expect_raises(Authz0::Error, /corrupt creds.json/) { reopened.creds }
    end
  end

  it "skips directories without a session.json in list" do
    SpecHelper.with_temp_home do |home|
      Authz0::Store::SessionStore.create("real", "https://x.com")
      # A stray directory with no metadata must not break listing.
      Dir.mkdir_p(File.join(home, "sessions", "stray"))
      # A directory whose session.json is garbage is skipped, not fatal.
      bad = File.join(home, "sessions", "bad")
      Dir.mkdir_p(bad)
      File.write(File.join(bad, "session.json"), "garbage")

      names = Authz0::Store::SessionStore.list.map(&.name)
      names.should eq(["real"])
    end
  end

  it "keeps cloned creds.json private (0600)" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("src", "https://x.com")
      s.save_creds([Authz0::Credential.new("u", headers: {"A" => "secret"})])
      clone = Authz0::Store::SessionStore.clone("src", "dst")
      (File.info(clone.creds_path).permissions.value & 0o077).should eq(0)
      clone.creds_world_readable?.should be_false
    end
  end

  it "refuses to rename onto an existing session" do
    SpecHelper.with_temp_home do
      Authz0::Store::SessionStore.create("a", "https://x.com")
      Authz0::Store::SessionStore.create("b", "https://x.com")
      expect_raises(Authz0::ConflictError) { Authz0::Store::SessionStore.rename("a", "b") }
      # both still exist after the failed rename
      Authz0::Store::SessionStore.exists?("a").should be_true
      Authz0::Store::SessionStore.exists?("b").should be_true
    end
  end

  it "detects a world-readable creds.json" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("w", "https://x.com")
      s.save_creds([Authz0::Credential.new("u", headers: {"A" => "B"})])
      s.creds_world_readable?.should be_false
      File.chmod(s.creds_path, 0o644)
      s.creds_world_readable?.should be_true
    end
  end
end
