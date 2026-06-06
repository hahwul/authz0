require "./spec_helper"

private def result(accessible, expected, verdict)
  Authz0::Result.new(0, "https://x/r", "GET", "user", ["admin"], [] of String,
    accessible: accessible, expected_access: expected, status_code: 200, resp_size: 0_i64, verdict: verdict)
end

describe "finding severity" do
  it "classifies unauthorized access as High" do
    r = result(true, false, "X") # reached something it shouldn't
    r.unauthorized?.should be_true
    r.over_restrictive?.should be_false
    r.severity.should eq(Authz0::Result::Severity::High)
    r.severity.label.should eq("high")
  end

  it "classifies over-restrictive denial as Low" do
    r = result(false, true, "X") # denied something it should reach
    r.over_restrictive?.should be_true
    r.unauthorized?.should be_false
    r.severity.should eq(Authz0::Result::Severity::Low)
    r.severity.label.should eq("low")
  end

  it "classifies expected outcomes as None" do
    result(true, true, "O").severity.should eq(Authz0::Result::Severity::None)
    result(false, false, "?").severity.should eq(Authz0::Result::Severity::None)
  end

  describe Authz0::Report::Summary do
    it "counts the two finding kinds separately" do
      results = [
        result(true, false, "X"), # unauthorized
        result(false, true, "X"), # over-restrictive
        result(false, true, "X"), # over-restrictive
        result(true, true, "O"),  # clean
      ]
      s = Authz0::Report::Summary.new(results)
      s.findings.should eq(3)
      s.unauthorized.should eq(1)
      s.over_restrictive.should eq(2)
      s.breached?.should be_true
    end

    it "is not 'breached' when only over-restrictive findings exist" do
      s = Authz0::Report::Summary.new([result(false, true, "X")])
      s.findings.should eq(1)
      s.breached?.should be_false
    end
  end

  describe "report severity mapping" do
    it "maps SARIF level by severity" do
      results = [result(true, false, "X"), result(false, true, "X")]
      sarif = JSON.parse(Authz0::Report.render(results, Authz0::Report::Format::Sarif, false))
      levels = sarif["runs"][0]["results"].as_a.map(&.["level"].as_s)
      levels.should contain("error")   # unauthorized
      levels.should contain("warning") # over-restrictive
    end

    it "includes severity + breakdown in JSON" do
      results = [result(true, false, "X")]
      doc = JSON.parse(Authz0::Report.render(results, Authz0::Report::Format::Json, false))
      doc["summary"]["unauthorized"].as_i.should eq(1)
      doc["results"][0]["severity"].as_s.should eq("high")
    end
  end
end
