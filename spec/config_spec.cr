require "./spec_helper"

describe Authz0::Settings do
  it "falls back to built-in defaults when unset" do
    s = Authz0::Settings.new
    s.effective_concurrency.should eq(Authz0::Settings::DEFAULT_CONCURRENCY)
    s.effective_timeout.should eq(Authz0::Settings::DEFAULT_TIMEOUT)
    s.effective_output.should eq(Authz0::Settings::DEFAULT_OUTPUT)
    s.retries.should be_nil
    s.follow_redirects.should be_nil
    s.user_agent.should be_nil
  end

  it "round-trips through JSON on disk" do
    SpecHelper.with_temp_home do
      s = Authz0::Settings.new
      s.proxy = "http://127.0.0.1:8080"
      s.concurrency = 33
      s.retries = 2
      s.follow_redirects = 5
      s.user_agent = "ua/1"
      s.save

      reloaded = Authz0::Settings.load(Authz0::Config.config_path)
      reloaded.proxy.should eq("http://127.0.0.1:8080")
      reloaded.effective_concurrency.should eq(33)
      reloaded.retries.should eq(2)
      reloaded.follow_redirects.should eq(5)
      reloaded.user_agent.should eq("ua/1")
    end
  end

  it "returns defaults for a missing or empty config file" do
    SpecHelper.with_temp_home do
      Authz0::Settings.load(Authz0::Config.config_path).effective_output.should eq("table")
      File.write(Authz0::Config.config_path, "   \n")
      Authz0::Settings.load(Authz0::Config.config_path).effective_output.should eq("table")
    end
  end

  it "raises ConfigError on malformed config JSON" do
    SpecHelper.with_temp_home do
      File.write(Authz0::Config.config_path, "{ not json")
      expect_raises(Authz0::ConfigError) { Authz0::Settings.load(Authz0::Config.config_path) }
    end
  end
end

describe Authz0::Config do
  it "honors AUTHZ0_HOME for paths" do
    SpecHelper.with_temp_home do |home|
      Authz0::Config.home.should eq(home)
      Authz0::Config.sessions_dir.should eq(File.join(home, "sessions"))
      Authz0::Config.config_path.should eq(File.join(home, "config.json"))
    end
  end

  it "expands a leading ~ against $HOME" do
    prev = ENV["HOME"]?
    ENV["HOME"] = "/tmp/fakehome"
    begin
      Authz0::Config.expand("~/x").should eq("/tmp/fakehome/x")
      Authz0::Config.expand("/abs/path").should eq("/abs/path")
    ensure
      prev ? (ENV["HOME"] = prev) : ENV.delete("HOME")
    end
  end
end
