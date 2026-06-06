require "./spec_helper"

describe Authz0::Validator do
  describe "#session_name!" do
    it "accepts safe names" do
      Authz0::Validator.session_name!("my-api.test_1").should eq("my-api.test_1")
    end

    it "rejects path separators and traversal" do
      expect_raises(Authz0::ValidationError) { Authz0::Validator.session_name!("a/b") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.session_name!("..") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.session_name!("../etc") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.session_name!("") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.session_name!("has space") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.session_name!("-leading") }
    end
  end

  describe "#base_url!" do
    it "accepts http(s) URLs" do
      Authz0::Validator.base_url!("https://api.example.com").should eq("https://api.example.com")
    end

    it "rejects non-http schemes and hostless URLs" do
      expect_raises(Authz0::ValidationError) { Authz0::Validator.base_url!("ftp://x") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.base_url!("notaurl") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.base_url!("") }
    end
  end

  describe "#header!" do
    it "splits on the first colon and trims" do
      Authz0::Validator.header!("Authorization: Bearer x:y").should eq({"Authorization", "Bearer x:y"})
    end

    it "rejects headers without a colon or name" do
      expect_raises(Authz0::ValidationError) { Authz0::Validator.header!("nope") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.header!(": value") }
    end
  end

  describe "#cookie!" do
    it "splits name=value" do
      Authz0::Validator.cookie!("sid=abc=def").should eq({"sid", "abc=def"})
    end

    it "rejects malformed cookies" do
      expect_raises(Authz0::ValidationError) { Authz0::Validator.cookie!("noequals") }
    end
  end

  describe "#csv" do
    it "trims, drops blanks, de-dupes" do
      Authz0::Validator.csv(" a, b ,a, ,c").should eq(["a", "b", "c"])
    end
  end

  describe "#status_list!" do
    it "parses valid status codes" do
      Authz0::Validator.status_list!("200, 201,204").should eq([200, 201, 204])
    end

    it "rejects out-of-range or non-numeric" do
      expect_raises(Authz0::ValidationError) { Authz0::Validator.status_list!("200,999999") }
      expect_raises(Authz0::ValidationError) { Authz0::Validator.status_list!("abc") }
    end
  end
end
