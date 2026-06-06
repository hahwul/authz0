require "./spec_helper"

# Locks in the fixes from the adversarial review pass so they can't regress.
describe "regressions (adversarial review)" do
  describe "path traversal" do
    it "rejects traversal names in open/delete/rename/clone" do
      SpecHelper.with_temp_home do
        Authz0::Store::SessionStore.create("real", "https://x.com")
        expect_raises(Authz0::ValidationError) { Authz0::Store::SessionStore.open("../../etc") }
        expect_raises(Authz0::ValidationError) { Authz0::Store::SessionStore.delete("../real") }
        expect_raises(Authz0::ValidationError) { Authz0::Store::SessionStore.rename("../real", "x") }
        expect_raises(Authz0::ValidationError) { Authz0::Store::SessionStore.clone("../real", "x") }
        # The legitimate session is untouched.
        Authz0::Store::SessionStore.exists?("real").should be_true
      end
    end
  end

  describe "creds.json is never world-readable" do
    it "stays 0600 across create and save" do
      SpecHelper.with_temp_home do
        s = Authz0::Store::SessionStore.create("p", "https://x.com")
        ((File.info(s.creds_path).permissions.value & 0o077)).should eq(0)
        s.save_creds([Authz0::Credential.new("u", headers: {"A" => "secret"})])
        ((File.info(s.creds_path).permissions.value & 0o077)).should eq(0)
        # No leftover temp file.
        File.exists?(s.creds_path + ".tmp").should be_false
      end
    end
  end

  describe "Importers.relativize origin matching" do
    it "treats explicit default ports as same-origin" do
      Authz0::Importers.relativize("https://api.example.com:443/x", "https://api.example.com").should eq("/x")
      Authz0::Importers.relativize("http://api.example.com:80/x", "http://api.example.com").should eq("/x")
    end

    it "is case-insensitive on host" do
      Authz0::Importers.relativize("https://API.Example.COM/x", "https://api.example.com").should eq("/x")
    end

    it "keeps a genuinely different port absolute" do
      Authz0::Importers.relativize("https://api.example.com:8443/x", "https://api.example.com")
        .should eq("https://api.example.com:8443/x")
    end
  end

  describe "Postman nil-safety" do
    it "does not crash on a non-hash url field" do
      pm = %({"item":[{"request":{"method":"GET","url":12345}}]})
      Authz0::Importers::Postman.new.parse(pm, "https://x.com").size.should eq(0)
    end

    it "skips non-object urlencoded entries" do
      pm = %({"item":[{"request":{"method":"POST","url":{"raw":"https://x.com/a"},"body":{"mode":"urlencoded","urlencoded":["bad",{"key":"k","value":"v"}]}}}]})
      targets = Authz0::Importers::Postman.new.parse(pm, "https://x.com")
      targets.size.should eq(1)
      targets[0].body.should eq("k=v")
    end
  end

  describe "global flag stripping" do
    it "does not consume a flag value that equals a global flag" do
      # `--body -q` : -q is the body value, not the global quiet flag.
      argv = ["url", "add", "s", "/x", "--body", "-q"]
      Authz0::CLI::Runner.apply_globals!(argv)
      argv.should eq(["url", "add", "s", "/x", "--body", "-q"])
      Authz0::Logger.quiet?.should be_false
    end

    it "still strips a real leading global flag" do
      argv = ["-q", "scan", "demo"]
      Authz0::CLI::Runner.apply_globals!(argv)
      argv.should eq(["scan", "demo"])
      Authz0::Logger.quiet?.should be_true
      Authz0::Logger.quiet = false # reset shared state
    end
  end

  describe "table display width" do
    it "counts CJK glyphs as two columns and aligns rows" do
      Authz0::Table.display_width("admin").should eq(5)
      Authz0::Table.display_width("관리자").should eq(6) # 3 wide glyphs
      t = Authz0::Table.new(["role"])
      t.add(["관리자"])
      t.add(["user"])
      lines = t.render(Authz0::Table::Style::Box, false).lines
      # Every rendered line shares the same visible width.
      widths = lines.map { |l| Authz0::Table.display_width(l) }.uniq!
      widths.size.should eq(1)
    end
  end
end
