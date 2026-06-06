require "./spec_helper"

private def res(index, verdict, accessible, expected, status = 200, elapsed = 0)
  Authz0::Result.new(index, "https://x/#{index}", "GET", "u", ["admin"], [] of String,
    accessible: accessible, expected_access: expected, status_code: status, resp_size: 0_i64,
    verdict: verdict, elapsed_ms: elapsed)
end

describe Authz0::Scan::Triage do
  # index0: unauthorized (high), index1: over-restrictive (low), index2: clean
  unauth = res(0, "X", true, false)
  over = res(1, "X", false, true)
  clean = res(2, "O", true, true)
  all = [unauth, over, clean]

  describe "#new_finding_ids" do
    it "returns findings not present in the baseline" do
      base = Set{over.identity} # over-restrictive already known
      ids = Authz0::Scan::Triage.new_finding_ids(all, base)
      ids.should eq(Set{unauth.identity})
    end

    it "returns all findings when baseline is empty" do
      Authz0::Scan::Triage.new_finding_ids(all, Set(String).new).size.should eq(2)
    end
  end

  describe "#filter" do
    empty = Set(String).new
    it "only_findings drops O rows" do
      Authz0::Scan::Triage.filter(all, true, nil, false, empty).map(&.index).should eq([0, 1])
    end

    it "severity high/low select disjoint sets" do
      Authz0::Scan::Triage.filter(all, false, "high", false, empty).map(&.index).should eq([0])
      Authz0::Scan::Triage.filter(all, false, "low", false, empty).map(&.index).should eq([1])
    end

    it "only_new keeps just the new findings" do
      new_ids = Set{unauth.identity}
      Authz0::Scan::Triage.filter(all, false, nil, true, new_ids).map(&.index).should eq([0])
    end
  end

  describe "#sort" do
    it "severity orders unauthorized, then over-restrictive, then rest" do
      Authz0::Scan::Triage.sort(all, "severity").map(&.index).should eq([0, 1, 2])
    end

    it "latency sorts slowest first" do
      a = res(0, "O", true, true, elapsed: 10)
      b = res(1, "O", true, true, elapsed: 99)
      Authz0::Scan::Triage.sort([a, b], "latency").map(&.index).should eq([1, 0])
    end

    it "nil field preserves order" do
      Authz0::Scan::Triage.sort(all, nil).map(&.index).should eq([0, 1, 2])
    end
  end
end
