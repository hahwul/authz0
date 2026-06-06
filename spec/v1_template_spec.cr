require "./spec_helper"

describe Authz0::Importers::V1Template do
  it "parses urls, credentials and asserts from a v1 template" do
    yaml = <<-YAML
    name: demo
    roles:
    - name: admin
    urls:
    - url: https://api.example.com/admin
      method: GET
      contentType: ""
      body: ""
      allowRole:
      - admin
      denyRole:
      - guest
      alias: admin panel
    - url: https://api.example.com/login
      method: POST
      contentType: json
      body: '{"u":1}'
      allowRole: []
      denyRole: []
    asserts:
    - type: success-status
      value: 200,201
    credentials:
    - rolename: admin
      headers:
      - 'Authorization: Bearer secret'
      - 'X-API-Key: abc'
    YAML

    parsed = Authz0::Importers::V1Template.new.parse(yaml)
    parsed.targets.size.should eq(2)

    admin = parsed.targets[0]
    admin.path.should eq("https://api.example.com/admin")
    admin.allow_roles.should eq(["admin"])
    admin.deny_roles.should eq(["guest"])
    admin.alias.should eq("admin panel")

    login = parsed.targets[1]
    login.method.should eq("POST")
    login.content_type.should eq("json")
    login.body.should eq(%({"u":1}))

    parsed.asserts.first.type.should eq("success-status")

    cred = parsed.creds.first
    cred.role.should eq("admin")
    cred.headers["Authorization"].should eq("Bearer secret")
    cred.headers["X-API-Key"].should eq("abc")

    # Base URL is derived from the first absolute target's origin.
    parsed.base_url.should eq("https://api.example.com")
  end

  it "raises ImportError on non-mapping input" do
    expect_raises(Authz0::ImportError) { Authz0::Importers::V1Template.new.parse("- just\n- a list") }
  end

  it "drives an ephemeral scan against a live server (no session)" do
    SpecHelper.with_test_server do |base|
      yaml = <<-YAML
      name: live
      urls:
      - url: #{base}/me
        allowRole: []
        denyRole: []
      - url: #{base}/secret
        allowRole:
        - admin
        denyRole: []
      asserts:
      - type: success-status
        value: 200,201
      - type: fail-status
        value: "403"
      credentials:
      - rolename: manager
        headers:
        - 'Authorization: Bearer managertoken'
      YAML

      parsed = Authz0::Importers::V1Template.new.parse(yaml)
      scanner = Authz0::Scan::Scanner.new(Authz0::Scan::Options.new(progress: false, timeout: 5))
      results = scanner.run(parsed.targets, parsed.creds, parsed.asserts, parsed.base_url)

      # manager reaching admin-only /secret is the one finding.
      results.count(&.vulnerable?).should eq(1)
      finding = results.find(&.vulnerable?).not_nil!
      finding.url.should end_with("/secret")
      finding.role.should eq("manager")
    end
  end
end
