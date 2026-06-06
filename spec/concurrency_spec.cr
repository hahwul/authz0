require "./spec_helper"

# Stresses the Scanner's pre-sized slots array + channel fan-out: with many
# jobs and high concurrency, every (target, cred) probe must land in its own
# slot — no losses, no duplicates, no cross-writes.
describe "scanner concurrency integrity" do
  it "produces exactly one correct result per (target, cred) under load" do
    SpecHelper.with_test_server do |base|
      n = 60
      roles = %w[a b c]
      targets = (0...n).map { |i| Authz0::TargetURL.new("/ep/#{i}", "GET") }
      creds = roles.map { |r| Authz0::Credential.new(r, headers: {"X-Role" => r}) }

      scanner = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(concurrency: 32, timeout: 5, progress: false))
      results = scanner.run(targets, creds, [] of Authz0::Assertion, base)

      # Exactly one probe per (target, cred).
      results.size.should eq(n * roles.size)
      results.all? { |r| r.status_code == 200 }.should be_true
      results.count(&.error).should eq(0)

      # Every target index appears once per role.
      by_index = results.group_by(&.index)
      by_index.size.should eq(n)
      by_index.each_value(&.size.should(eq(roles.size)))

      # The echoed URL must match the slot's index — proof no worker wrote into
      # another's slot.
      results.each do |r|
        r.url.should end_with("/ep/#{r.index}")
      end

      # And each (index, role) pair is unique.
      pairs = results.map { |r| {r.index, r.role} }
      pairs.uniq.size.should eq(results.size)
    end
  end
end
