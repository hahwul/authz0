require "./spec_helper"

private BASE = "https://api.example.com"

describe Authz0::Importers do
  describe "#relativize" do
    it "relativizes same-origin urls and keeps cross-origin absolute" do
      Authz0::Importers.relativize("https://api.example.com/a?b=1", BASE).should eq("/a?b=1")
      Authz0::Importers.relativize("https://other.com/a", BASE).should eq("https://other.com/a")
      Authz0::Importers.relativize("/bare", BASE).should eq("/bare")
    end
  end
end

describe Authz0::Importers::Urls do
  it "parses bare urls and METHOD-prefixed lines, skipping comments" do
    content = "POST /login\n/admin\n# a comment\n\nhttps://other.com/x\n"
    targets = Authz0::Importers::Urls.new.parse(content, BASE)
    targets.map { |t| {t.method, t.path} }.should eq([
      {"POST", "/login"}, {"GET", "/admin"}, {"GET", "https://other.com/x"},
    ])
  end
end

describe Authz0::Importers::Har do
  it "reads method, url, and json body" do
    har = %({"log":{"entries":[
      {"request":{"method":"GET","url":"https://api.example.com/users"}},
      {"request":{"method":"POST","url":"https://api.example.com/users","postData":{"mimeType":"application/json","text":"{\\"a\\":1}"}}}
    ]}})
    targets = Authz0::Importers::Har.new.parse(har, BASE)
    targets.size.should eq(2)
    targets[1].method.should eq("POST")
    targets[1].content_type.should eq("json")
    targets[1].body.should eq(%({"a":1}))
  end

  it "raises ImportError on malformed JSON" do
    expect_raises(Authz0::ImportError) { Authz0::Importers::Har.new.parse("{bad", BASE) }
  end
end

describe Authz0::Importers::Burp do
  it "decodes the request body from base64" do
    raw = "POST /b HTTP/1.1\r\nHost: api.example.com\r\n\r\n{\"x\":1}"
    b64 = Base64.encode(raw)
    xml = %(<items><item><url>https://api.example.com/b</url><method>POST</method><request base64="true">#{b64}</request></item></items>)
    targets = Authz0::Importers::Burp.new.parse(xml, BASE)
    targets.size.should eq(1)
    targets[0].path.should eq("/b")
    targets[0].body.should eq(%({"x":1}))
    targets[0].content_type.should eq("json")
  end
end

describe Authz0::Importers::OpenAPI do
  it "expands paths × methods with the server prefix" do
    spec = <<-YAML
    openapi: 3.0.0
    servers:
      - url: https://api.example.com/v1
    paths:
      /pets:
        get: {}
        post:
          requestBody:
            content:
              application/json: {}
    YAML
    targets = Authz0::Importers::OpenAPI.new.parse(spec, BASE)
    targets.map { |t| {t.method, t.path} }.sort_by { |m, _| m }.should eq([
      {"GET", "/v1/pets"}, {"POST", "/v1/pets"},
    ])
    targets.find { |t| t.method == "POST" }.not_nil!.content_type.should eq("json")
  end

  it "handles swagger 2 host+basePath" do
    spec = %({"swagger":"2.0","host":"api.example.com","basePath":"/v2","schemes":["https"],"paths":{"/x":{"get":{}}}})
    targets = Authz0::Importers::OpenAPI.new.parse(spec, BASE)
    targets.first.path.should eq("/v2/x")
  end
end

describe Authz0::Importers::Postman do
  it "walks folders and extracts requests" do
    pm = %({"info":{},"item":[{"name":"f","item":[
      {"name":"login","request":{"method":"POST","url":{"raw":"https://api.example.com/login"},"body":{"mode":"raw","raw":"{\\"u\\":1}"}}}
    ]}]})
    targets = Authz0::Importers::Postman.new.parse(pm, BASE)
    targets.size.should eq(1)
    targets[0].method.should eq("POST")
    targets[0].path.should eq("/login")
    targets[0].content_type.should eq("json")
  end

  it "substitutes collection {{variables}} and leaves unknown ones literal" do
    pm = %({"variable":[{"key":"baseUrl","value":"https://api.example.com"},{"key":"ver","value":"v2"}],
      "item":[
        {"name":"a","request":{"method":"GET","url":{"raw":"{{baseUrl}}/{{ver}}/me"}}},
        {"name":"b","request":{"method":"GET","url":{"raw":"{{baseUrl}}/{{missing}}/x"}}}
      ]})
    targets = Authz0::Importers::Postman.new.parse(pm, BASE)
    targets[0].path.should eq("/v2/me")
    targets[1].path.should eq("/{{missing}}/x")
    targets[1].templated?.should be_true
  end
end

describe "Importers.merge" do
  it "adds new targets and skips duplicates by id" do
    SpecHelper.with_temp_home do
      s = Authz0::Store::SessionStore.create("m", BASE)
      first = [Authz0::TargetURL.new("/a", "GET"), Authz0::TargetURL.new("/b", "GET")]
      added, skipped = Authz0::Importers.merge(s, first)
      added.should eq(2)
      skipped.should eq(0)

      again = [Authz0::TargetURL.new("/a", "GET"), Authz0::TargetURL.new("/c", "GET")]
      added2, skipped2 = Authz0::Importers.merge(s, again)
      added2.should eq(1)
      skipped2.should eq(1)
      Authz0::Store::SessionStore.open("m").urls.size.should eq(3)
    end
  end
end
