require "./spec_helper"

describe Authz0::CurlParser do
  it "extracts headers and cookies from a browser copy-as-cURL" do
    cmd = <<-CURL
    curl 'https://api.example.com/me' \\
      -H 'Authorization: Bearer abc.def' \\
      -H 'X-Csrf: tok' \\
      -b 'session=sid; theme=dark' \\
      --compressed
    CURL
    parsed = Authz0::CurlParser.parse(cmd)
    parsed.headers["Authorization"].should eq("Bearer abc.def")
    parsed.headers["X-Csrf"].should eq("tok")
    parsed.cookies["session"].should eq("sid")
    parsed.cookies["theme"].should eq("dark")
  end

  it "handles --header=VALUE and double quotes" do
    parsed = Authz0::CurlParser.parse(%(curl "https://x" --header="X-Key: v1" -H "Accept: */*"))
    parsed.headers["X-Key"].should eq("v1")
    parsed.headers["Accept"].should eq("*/*")
  end

  it "returns empty maps for a curl with no auth material" do
    parsed = Authz0::CurlParser.parse("curl https://x -X POST --data 'a=1'")
    parsed.headers.should be_empty
    parsed.cookies.should be_empty
  end

  it "raises on an unbalanced quote instead of swallowing later args" do
    expect_raises(Authz0::ValidationError, /unbalanced quote/) do
      Authz0::CurlParser.parse("curl https://x -H 'Authorization: Bearer abc")
    end
  end
end
