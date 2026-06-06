require "./spec_helper"

private BASE = "https://api.example.com"

# Quality round: every importer must handle messy/hostile input by returning an
# empty list or raising a clean ImportError — never an uncaught crash.
describe "importer hardening" do
  describe Authz0::Importers::Urls do
    it "handles empty / comment-only / whitespace input" do
      i = Authz0::Importers::Urls.new
      i.parse("", BASE).should be_empty
      i.parse("# only a comment\n\n   \n", BASE).should be_empty
      i.parse("   \t  \n", BASE).should be_empty
    end

    it "keeps a lone token as a GET path" do
      Authz0::Importers::Urls.new.parse("notamethod /x", BASE).map(&.path).should eq(["notamethod /x"])
    end
  end

  describe Authz0::Importers::Har do
    it "tolerates missing/empty structures" do
      h = Authz0::Importers::Har.new
      h.parse("{}", BASE).should be_empty
      h.parse(%({"log":{}}), BASE).should be_empty
      h.parse(%({"log":{"entries":[]}}), BASE).should be_empty
      h.parse(%({"log":{"entries":[{},{"request":null}]}}), BASE).should be_empty
    end

    it "skips entries with an empty url" do
      Authz0::Importers::Har.new.parse(%({"log":{"entries":[{"request":{"method":"GET","url":""}}]}}), BASE).should be_empty
    end

    it "raises ImportError (not a crash) on non-JSON" do
      expect_raises(Authz0::ImportError) { Authz0::Importers::Har.new.parse("<xml/>", BASE) }
    end
  end

  describe Authz0::Importers::Burp do
    it "tolerates empty/childless XML" do
      b = Authz0::Importers::Burp.new
      b.parse("<items></items>", BASE).should be_empty
      b.parse("<items><item></item></items>", BASE).should be_empty # no url
    end

    it "handles a bad base64 request without crashing" do
      xml = %(<items><item><url>https://api.example.com/x</url><method>GET</method><request base64="true">!!!notb64!!!</request></item></items>)
      Authz0::Importers::Burp.new.parse(xml, BASE).size.should eq(1)
    end

    it "handles malformed XML gracefully (libxml2 is lenient: empty or ImportError, never a crash)" do
      result =
        begin
          Authz0::Importers::Burp.new.parse("<items><item>", BASE)
        rescue Authz0::ImportError
          [] of Authz0::TargetURL
        end
      result.should be_empty
    end
  end

  describe Authz0::Importers::OpenAPI do
    it "raises ImportError when there is no paths object" do
      expect_raises(Authz0::ImportError) { Authz0::Importers::OpenAPI.new.parse(%({"openapi":"3.0.0"}), BASE) }
    end

    it "ignores a path-level 'parameters' key (not an HTTP method)" do
      spec = %({"openapi":"3.0.0","paths":{"/x":{"parameters":[{"name":"id"}],"get":{}}}})
      targets = Authz0::Importers::OpenAPI.new.parse(spec, BASE)
      targets.map(&.method).should eq(["GET"])
    end

    it "tolerates a non-mapping path value" do
      spec = %({"openapi":"3.0.0","paths":{"/x":"oops","/y":{"get":{}}}})
      Authz0::Importers::OpenAPI.new.parse(spec, BASE).map(&.path).should eq(["/y"])
    end

    it "tolerates a non-mapping operation value (get: \"string\")" do
      spec = %({"openapi":"3.0.0","paths":{"/a":{"get":"oops"},"/b":{"post":{"requestBody":{"content":{"application/json":{}}}}}}})
      targets = Authz0::Importers::OpenAPI.new.parse(spec, BASE)
      targets.map { |t| {t.method, t.path} }.should eq([{"GET", "/a"}, {"POST", "/b"}])
      targets.find! { |t| t.method == "POST" }.content_type.should eq("json")
    end

    it "raises ImportError on a non-mapping root" do
      expect_raises(Authz0::ImportError) { Authz0::Importers::OpenAPI.new.parse("- a\n- b", BASE) }
    end
  end

  describe Authz0::Importers::Postman do
    it "raises ImportError without an item array" do
      expect_raises(Authz0::ImportError) { Authz0::Importers::Postman.new.parse(%({"info":{}}), BASE) }
    end

    it "tolerates a request url that is a bare number or array" do
      pm = %({"item":[
        {"request":{"method":"GET","url":12345}},
        {"request":{"method":"GET","url":["a","b"]}},
        {"request":{"method":"GET","url":{"raw":"https://api.example.com/ok"}}}
      ]})
      Authz0::Importers::Postman.new.parse(pm, BASE).map(&.path).should eq(["/ok"])
    end

    it "tolerates a request that is itself a non-hash value" do
      pm = %({"item":[
        {"request":12345},
        {"request":[]},
        {"request":true},
        {"request":{"method":"GET","url":{"raw":"https://api.example.com/ok"}}}
      ]})
      Authz0::Importers::Postman.new.parse(pm, BASE).map(&.path).should eq(["/ok"])
    end

    it "walks deeply nested folders" do
      pm = %({"item":[{"item":[{"item":[{"request":{"method":"GET","url":{"raw":"https://api.example.com/deep"}}}]}]}]})
      Authz0::Importers::Postman.new.parse(pm, BASE).map(&.path).should eq(["/deep"])
    end
  end

  describe Authz0::Importers::V1Template do
    it "tolerates missing sections" do
      parsed = Authz0::Importers::V1Template.new.parse("name: x")
      parsed.targets.should be_empty
      parsed.creds.should be_empty
      parsed.asserts.should be_empty
    end

    it "skips malformed credential header lines" do
      yaml = <<-YAML
      urls: []
      credentials:
      - rolename: u
        headers:
        - 'no-colon-here'
        - 'X-Ok: yes'
      YAML
      cred = Authz0::Importers::V1Template.new.parse(yaml).creds.first
      cred.headers.should eq({"X-Ok" => "yes"})
    end
  end
end
