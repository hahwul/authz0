require "./spec_helper"

private def r(url, role = "u", verdict = "O", acc = true, exp = true)
  Authz0::Result.new(0, url, "GET", role, [] of String, [] of String,
    accessible: acc, expected_access: exp, status_code: 200, resp_size: 0_i64, verdict: verdict)
end

# Quality round: every reporter must render any input — including empty sets and
# fields carrying delimiters/markup — without crashing or corrupting structure.
describe "reporter hardening" do
  it "renders empty results in every format without crashing" do
    empty = [] of Authz0::Result
    Authz0::Report::Format.names.each do |name|
      fmt = Authz0::Report::Format.parse?(name).not_nil!
      rendered = Authz0::Report.render(empty, fmt, false)
      rendered.should_not be_nil
    end
  end

  it "produces valid JSON / SARIF for empty results" do
    empty = [] of Authz0::Result
    JSON.parse(Authz0::Report.render(empty, Authz0::Report::Format::Json, false))["summary"]["probes"].as_i.should eq(0)
    sarif = JSON.parse(Authz0::Report.render(empty, Authz0::Report::Format::Sarif, false))
    sarif["runs"][0]["results"].as_a.should be_empty
  end

  it "escapes pipes in Markdown cells (no column desync)" do
    rows = [r("https://x/a|b|c")]
    md = Authz0::Report.render(rows, Authz0::Report::Format::Markdown, false)
    md.should contain("a\\|b\\|c")
  end

  it "neutralizes backticks in the Markdown findings list" do
    rows = [r("https://x/`whoami`", "u", "X", true, false)]
    md = Authz0::Report.render(rows, Authz0::Report::Format::Markdown, false)
    md.should contain("## Findings")
    md.should_not contain("`GET https://x/`whoami``") # backtick replaced, span intact
  end

  it "CSV round-trips fields containing commas, quotes and newlines" do
    rows = [r(%(https://x/a,"q"#{"\n"}b))]
    csv = Authz0::Report.render(rows, Authz0::Report::Format::Csv, false)
    parsed = CSV.parse(csv)
    parsed.size.should eq(2)
    parsed[1][3].should eq(%(https://x/a,"q"#{"\n"}b))
  end

  it "HTML-escapes every rendered field, not just the url" do
    rows = [r("https://x/<b>", "<role>", "X", true, false)]
    html = Authz0::Report.render(rows, Authz0::Report::Format::Html, false)
    html.should_not contain("<role>")
    html.should contain("&lt;role&gt;")
  end
end
