require 'spec_helper'

describe OmniAuth::Strategies::Crowd, :type=>:strategy do
  include OmniAuth::Test::StrategyTestCase
  def strategy
    @crowd_server_url ||= 'https://crowd.example.org'
    @application_name ||= 'bogus_app'
    @application_password ||= 'bogus_app_password'
    [OmniAuth::Strategies::Crowd, {:crowd_server_url => @crowd_server_url,
                                    :application_name => @application_name,
                                    :application_password => @application_password,
                                    :use_sessions => @using_sessions}]
  end

  @using_sessions = false
  let(:config) { OmniAuth::Strategies::Crowd::Configuration.new(strategy[1]) }
  let(:validator) { OmniAuth::Strategies::Crowd::CrowdValidator.new(config, 'foo', 'bar') }

  describe 'Authentication Request Body' do

    it 'should send password in session request' do
      body = <<-BODY.strip
<password>
  <value>bar</value>
</password>
BODY
      expect(validator.send(:make_authentication_request_body, 'bar')).to eq(body)
    end

    it 'should escape special characters username and password in session request' do
      body = <<-BODY.strip
<password>
  <value>bar&lt;</value>
</password>
BODY
      expect(validator.send(:make_authentication_request_body, 'bar<')).to eq(body)
    end
  end

  describe 'Session Request Body' do
    it 'should send username and password in session request' do
      body = <<-BODY.strip
<authentication-context>
  <username>foo</username>
  <password>bar</password>
</authentication-context>
BODY
      expect(validator.send(:make_session_request_body, 'foo', 'bar')).to eq(body)
    end

    it 'should escape special characters username and password in session request' do
      body = <<-BODY.strip
<authentication-context>
  <username>foo</username>
  <password>bar&lt;</password>
</authentication-context>
BODY
      expect(validator.send(:make_session_request_body, 'foo', 'bar<')).to eq(body)
    end
  end

  describe 'GET /auth/crowd' do
    it 'should show the login form' do
      get '/auth/crowd'
      expect(last_response).to be_ok
    end
  end

  describe 'POST /auth/crowd' do
    it 'should redirect to callback' do
      post '/auth/crowd', :username=>'foo', :password=>'bar'
      expect(last_response).to be_redirect
      expect(last_response.headers['Location']).to eq('http://example.org/auth/crowd/callback')
    end
  end

  describe 'GET /auth/crowd/callback without any credentials' do
    it 'should fail' do
      get '/auth/crowd/callback'
      expect(last_response).to be_redirect
      expect(last_response.headers['Location']).to match(/no_credentials/)
    end
  end

  describe 'GET /auth/crowd/callback with credentials can be successful' do
    context "when using authentication endpoint" do
      before do
        stub_request(:post, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/authentication?username=foo").
        to_return(:body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'success.xml')))

        stub_request(:get, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/user/group/direct?username=foo").
            to_return(:body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'groups.xml')))

        #Adding this to prevent Content-Type text/xml from being added back in the future
        stub_request(:get, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/user/group/direct?username=foo").with(:headers => {"Content-Type" => "text/xml"}).
            to_return(:status => [415, "Unsupported Media Type"])
        get '/auth/crowd/callback', nil, 'rack.session'=>{'omniauth.crowd'=> {"username"=>"foo", "password"=>"ba"}}
      end
      it 'should call through to the master app' do
        expect(last_response.body).to eq('true')
      end
      it 'should have an auth hash' do
        auth = last_request.env['omniauth.auth']
        expect(auth).to be_kind_of(Hash)
      end
      it 'should have good data' do
        auth = last_request.env['omniauth.auth']
        expect(auth['provider']).to eq(:crowd)
        expect(auth['uid']).to eq('foo')
        expect(auth['info']).to be_kind_of(Hash)
        expect(auth['info']['groups'].sort).to eq(["Developers", "jira-users"].sort)
      end
    end

    describe "when using session endpoint" do
      before do
        @using_sessions = true
        stub_request(:post, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/authentication?username=foo").
          to_return(:body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'success.xml')))
        stub_request(:post, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/session").
          to_return(:status => 201, :body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'session.xml')))
        stub_request(:get, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/user/group/direct?username=foo").
          to_return(:body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'groups.xml')))
      end

      after { @using_sessions = false }

      it 'should call through to the master app' do
        get '/auth/crowd/callback', nil, 'rack.session'=>{'omniauth.crowd'=> {"username"=>"foo", "password"=>"ba"}}
        expect(last_response.body).to eq('true')
      end

      it 'should have an auth hash' do
        get '/auth/crowd/callback', nil, 'rack.session'=>{'omniauth.crowd'=> {"username"=>"foo", "password"=>"ba"}}
        expect(last_request.env['omniauth.auth']).to be_kind_of(Hash)
      end

      it 'should have good data' do
        get '/auth/crowd/callback', nil, 'rack.session'=>{'omniauth.crowd'=> {"username"=>"foo", "password"=>"ba"}}
        puts last_request.env['omniauth.auth']
        expect(auth['provider']).to eq(:crowd)
        expect(auth['uid']).to eq('foo')
        expect(auth['info']).to be_kind_of(Hash)
        expect(auth['info']['sso_token']).to eq('rtk8eMvqq00EiGn5iJCMZQ00')
        expect(auth['info']['groups'].sort).to eq(["Developers", "jira-users"].sort)
      end
    end
  end

  describe 'GET /auth/crowd/callback with credentials will fail' do
    before do
      stub_request(:post, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/authentication?username=foo").
      to_return(:code=>400)
      get '/auth/crowd/callback', nil, 'rack.session'=>{'omniauth.crowd'=> {"username"=>"foo", "password"=>"ba"}}
    end
    it 'should fail' do
      expect(last_response).to be_redirect
      expect(last_response.headers['Location']).to match(/invalid_credentials/)
    end
  end
end
