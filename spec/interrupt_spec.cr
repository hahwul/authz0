require "./spec_helper"
require "./cli_spec" # for CLISpec.bin / CLISpec.run
require "http/server"

# Interrupt safety: a terminal Ctrl-C sends SIGINT, and without an explicit
# trap SIGINT does NOT stop a running scan (its fibers sit blocked in socket
# reads) — so a slow scan couldn't be cancelled. The runner now traps INT/TERM
# and exits with the conventional 128+signal code.
describe "interrupt handling" do
  it "stops a running scan on SIGINT and exits 130" do
    # Server holds each connection open long enough that the scan is provably
    # mid-flight when we signal it — so a non-zero/clean exit can only come from
    # the trap, never from the scan finishing on its own.
    server = HTTP::Server.new do |ctx|
      sleep 3.seconds
      ctx.response.print "ok"
    end
    addr = server.bind_tcp("127.0.0.1", 0)
    spawn { server.listen }
    Fiber.yield

    SpecHelper.with_temp_home do |home|
      env = {"AUTHZ0_HOME" => home, "NO_COLOR" => "1", "AUTHZ0_YES" => "1"}
      CLISpec.run(["session", "new", "s", "--base-url", "http://127.0.0.1:#{addr.port}"], home)
      CLISpec.run(["url", "add", "s", "/slow"], home)

      proc = Process.new(CLISpec.bin, ["scan", "s", "--concurrency", "1", "-q"],
        env: env, output: Process::Redirect::Close, error: Process::Redirect::Close)
      sleep 0.8.seconds # let it reach the blocking read (trap is armed even earlier)
      proc.signal(Signal::INT)
      status = proc.wait
      status.exit_code.should eq(130)

      # The scan didn't complete, so nothing was archived (no torn/partial write).
      results = File.join(home, "sessions", "s", "results")
      (Dir.exists?(results) ? Dir.children(results).size : 0).should eq(0)
    end
  ensure
    server.try &.close
  end
end
