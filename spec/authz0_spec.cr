require "./spec_helper"

describe Authz0 do
  it "exposes a version" do
    Authz0::VERSION.should eq("2.0.0")
  end
end

describe Authz0::ShortId do
  it "is stable for the same request shape" do
    a = Authz0::ShortId.for("GET", "/admin", "")
    b = Authz0::ShortId.for("GET", "/admin", "")
    a.should eq(b)
    a.size.should eq(8)
  end

  it "differs by method/path/body" do
    Authz0::ShortId.for("GET", "/a").should_not eq(Authz0::ShortId.for("POST", "/a"))
    Authz0::ShortId.for("GET", "/a").should_not eq(Authz0::ShortId.for("GET", "/b"))
  end

  it "recognizes its own id shape" do
    Authz0::ShortId.looks_like?(Authz0::ShortId.for("GET", "/x")).should be_true
    Authz0::ShortId.looks_like?("nothex!!").should be_false
    Authz0::ShortId.looks_like?("abc").should be_false
  end
end

describe Authz0::Masking do
  it "fully stars short values" do
    Authz0::Masking.mask("1234").should eq("****")
  end

  it "keeps head/tail of long values" do
    Authz0::Masking.mask("Bearer abcdef123456").should eq("Bear…3456")
  end

  it "masks header values but keeps the key" do
    Authz0::Masking.mask_header("Authorization", "supersecrettoken").should eq("Authorization: supe…oken")
  end
end
