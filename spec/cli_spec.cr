require "./spec_helper"

# End-to-end CLI tests: build the real binary once and drive it as a subprocess,
# asserting exit codes and output. This exercises the command wiring (dispatch,
# option parsing, error → exit-code mapping) that the unit specs don't.
module CLISpec
  @@bin : String? = nil

  def self.bin : String
    @@bin ||= begin
      path = File.tempname("authz0-cli")
      buf = IO::Memory.new
      status = Process.run("crystal", ["build", "src/main.cr", "-o", path], output: buf, error: buf)
      raise "authz0 build failed:\n#{buf}" unless status.success?
      at_exit { File.delete(path) if File.exists?(path) }
      path
    end
  end

  record Run, status : Int32, stdout : String, stderr : String

  def self.run(args : Array(String), home : String, input : String? = nil) : Run
    stdout_buf = IO::Memory.new
    stderr_buf = IO::Memory.new
    stdin = input ? IO::Memory.new(input) : Process::Redirect::Close
    status = Process.run(bin, args,
      env: {"AUTHZ0_HOME" => home, "NO_COLOR" => "1", "AUTHZ0_YES" => "1"},
      output: stdout_buf, error: stderr_buf, input: stdin)
    Run.new(status.exit_code, stdout_buf.to_s, stderr_buf.to_s)
  end
end

describe "authz0 CLI (end-to-end)" do
  it "prints the version and exits 0" do
    SpecHelper.with_temp_home do |home|
      r = CLISpec.run(["version"], home)
      r.status.should eq(0)
      r.stdout.strip.should eq(Authz0::VERSION)
    end
  end

  it "maps errors to distinct exit codes" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["frobnicate"], home).status.should eq(1)     # unknown command
      CLISpec.run(["session", "new"], home).status.should eq(2) # validation (missing name)
      CLISpec.run(["scan", "ghost"], home).status.should eq(3)  # not found
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.com"], home).status.should eq(0)
      CLISpec.run(["scan", "s"], home).status.should eq(2) # no urls (validation)
    end
  end

  it "builds a session and scans a live server with the right exit code" do
    SpecHelper.with_temp_home do |home|
      SpecHelper.with_test_server do |base|
        CLISpec.run(["session", "new", "s", "--base-url", base], home).status.should eq(0)
        CLISpec.run(["url", "add", "s", "/secret", "--allow-role", "admin"], home).status.should eq(0)
        CLISpec.run(["assert", "add", "s", "--success-status", "200,201"], home).status.should eq(0)

        # /secret is open to all → an anonymous probe is an unauthorized finding.
        clean = CLISpec.run(["scan", "s", "--anon", "--no-progress", "-q", "--output", "json"], home)
        clean.status.should eq(0) # findings exist but no --fail-on-findings
        doc = JSON.parse(clean.stdout)
        doc["summary"]["unauthorized"].as_i.should be > 0

        failed = CLISpec.run(["scan", "s", "--anon", "--fail-on-findings", "--no-progress", "-q", "--output", "json"], home)
        failed.status.should eq(1)
      end
    end
  end

  it "emits shell completions and rejects unknown shells" do
    SpecHelper.with_temp_home do |home|
      %w[bash zsh fish].each do |shell|
        r = CLISpec.run(["completion", shell], home)
        r.status.should eq(0)
        r.stdout.should contain("authz0")
      end
      CLISpec.run(["completion", "powershell"], home).status.should eq(2)
    end
  end

  it "imports urls from stdin" do
    SpecHelper.with_temp_home do |home|
      CLISpec.run(["session", "new", "s", "--base-url", "https://x.com"], home)
      r = CLISpec.run(["import", "urls", "s", "-"], home, input: "/a\nPOST /b\n")
      r.status.should eq(0)
      CLISpec.run(["url", "list", "s"], home).stdout.lines.size.should eq(2)
    end
  end

  it "scans a v1 template ephemerally without a session" do
    SpecHelper.with_temp_home do |home|
      SpecHelper.with_test_server do |base|
        tmpl = File.tempname("tmpl") + ".yaml"
        File.write(tmpl, <<-YAML)
        name: t
        urls:
        - url: #{base}/secret
          allowRole: [admin]
          denyRole: []
        asserts:
        - type: success-status
          value: "200,201"
        YAML
        begin
          r = CLISpec.run(["scan", "--template", tmpl, "--anon", "--no-progress", "-q", "--output", "json"], home)
          r.status.should eq(0)
          JSON.parse(r.stdout)["summary"]["unauthorized"].as_i.should be > 0
          # ephemeral: no session created
          CLISpec.run(["session", "list", "--json"], home).stdout.should contain("[]")
        ensure
          File.delete(tmpl) if File.exists?(tmpl)
        end
      end
    end
  end
end
