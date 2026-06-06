require "./spec_helper"

private def sample_results
  [
    Authz0::Result.new(0, "https://x/admin", "GET", "user", ["admin"], [] of String,
      accessible: true, expected_access: false, status_code: 200, resp_size: 10_i64, verdict: "X"),
    Authz0::Result.new(1, "https://x/me", "GET", "user", [] of String, [] of String,
      accessible: true, expected_access: true, status_code: 200, resp_size: 5_i64, verdict: "O"),
    Authz0::Result.new(2, "https://x/down", "GET", "admin", ["admin"], [] of String,
      accessible: false, expected_access: false, status_code: 0, resp_size: 0_i64, verdict: "?", error: "timeout"),
  ]
end

describe Authz0::Report::Summary do
  it "counts targets, probes, findings, errors" do
    s = Authz0::Report::Summary.new(sample_results)
    s.total.should eq(3)
    s.findings.should eq(1)
    s.errors.should eq(1)
    s.targets.should eq(3)
    s.clean?.should be_false
  end
end

describe Authz0::Report do
  it "parses format names and aliases" do
    Authz0::Report::Format.parse?("md").should eq(Authz0::Report::Format::Markdown)
    Authz0::Report::Format.parse?("text").should eq(Authz0::Report::Format::Plain)
    Authz0::Report::Format.parse?("bogus").should be_nil
  end

  it "renders a plain table with a summary" do
    rendered = Authz0::Report.render(sample_results, Authz0::Report::Format::Plain, false)
    rendered.should contain("admin")
    rendered.should contain("1 findings")
  end

  it "renders valid JSON with summary and results" do
    rendered = Authz0::Report.render(sample_results, Authz0::Report::Format::Json, false)
    parsed = JSON.parse(rendered)
    parsed["tool"].as_s.should eq("authz0")
    parsed["summary"]["findings"].as_i.should eq(1)
    parsed["results"].as_a.size.should eq(3)
  end

  it "renders valid SARIF with only actionable results" do
    rendered = Authz0::Report.render(sample_results, Authz0::Report::Format::Sarif, false)
    parsed = JSON.parse(rendered)
    parsed["version"].as_s.should eq("2.1.0")
    # X (error) + ? (note) are reported; the O row is omitted.
    parsed["runs"][0]["results"].as_a.size.should eq(2)
    parsed["runs"][0]["results"][0]["level"].as_s.should eq("error")
  end

  it "renders Markdown with a findings section" do
    rendered = Authz0::Report.render(sample_results, Authz0::Report::Format::Markdown, false)
    rendered.should contain("## Findings")
    rendered.should contain("| # ")
  end

  it "renders self-contained HTML" do
    rendered = Authz0::Report.render(sample_results, Authz0::Report::Format::Html, false)
    rendered.should contain("<!doctype html>")
    rendered.should contain("class=\"finding\"")
  end

  it "escapes HTML in result fields" do
    evil = [Authz0::Result.new(0, "https://x/<script>", "GET", "u", [] of String, [] of String,
      accessible: true, expected_access: true, status_code: 200, resp_size: 0_i64, verdict: "O")]
    rendered = Authz0::Report.render(evil, Authz0::Report::Format::Html, false)
    rendered.should_not contain("/<script>")
    rendered.should contain("&lt;script&gt;")
  end
end
