require File.dirname(__FILE__) + '/../../spec_helper'

describe OmniAuth::Strategies::Crowd, :type=>:strategy do
  include OmniAuth::Test::StrategyTestCase
  @use_sessions = false
  def strategy
    @crowd_server_url ||= 'https://crowd.example.org'
    @application_name ||= 'bogus_app'
    @application_password ||= 'bogus_app_password'
    [OmniAuth::Strategies::Crowd, {:crowd_server_url => @crowd_server_url,
                                    :application_name => @application_name,
                                    :application_password => @application_password,
                                    :use_sessions => @use_sessions}]
  end

  describe 'Authentication Request Body' do
    before do
      config = OmniAuth::Strategies::Crowd::Configuration.new(strategy[1])
      @validator = OmniAuth::Strategies::Crowd::CrowdValidator.new(config, 'foo', 'bar')
    end

    it 'should send password in session request' do
      @validator.send(:make_authentication_request_body, 'bar').should == <<-BODY.strip
<password>
  <value>bar</value>
</password>
BODY
    end

    it 'should escape special characters username and password in session request' do
      @validator.send(:make_authentication_request_body, 'bar<').should == <<-BODY.strip
<password>
  <value>bar&lt;</value>
</password>
BODY
    end
  end

  describe 'Session Request Body' do
    before do
      config = OmniAuth::Strategies::Crowd::Configuration.new(strategy[1])
      @validator = OmniAuth::Strategies::Crowd::CrowdValidator.new(config, 'foo', 'bar')
    end

    it 'should send username and password in session request' do
      @validator.send(:make_session_request_body, 'foo', 'bar').should == <<-BODY.strip
<authentication-context>
  <username>foo</username>
  <password>bar</password>
</authentication-context>
BODY
    end

    it 'should escape special characters username and password in session request' do
      @validator.send(:make_session_request_body, 'foo', 'bar<').should == <<-BODY.strip
<authentication-context>
  <username>foo</username>
  <password>bar&lt;</password>
</authentication-context>
BODY
    end
  end

  describe 'GET /auth/crowd' do
    before do
      get '/auth/crowd'
    end

    it 'should show the login form' do
      last_response.should be_ok
    end
  end

  describe 'POST /auth/crowd' do
    before do
      post '/auth/crowd', :username=>'foo', :password=>'bar'
    end

    it 'should redirect to callback' do
      last_response.should be_redirect
      last_response.headers['Location'].should == 'http://example.org/auth/crowd/callback'
    end
  end

  describe 'GET /auth/crowd/callback without any credentials' do
    before do
      get '/auth/crowd/callback'
    end
    it 'should fail' do
      last_response.should be_redirect
      last_response.headers['Location'].should =~ /no_credentials/
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
        last_response.body.should == 'true'
      end
      it 'should have an auth hash' do
        auth = last_request.env['omniauth.auth']
        auth.should be_kind_of(Hash)
      end
      it 'should have good data' do
        auth = last_request.env['omniauth.auth']
        auth['provider'].should == :crowd
        auth['uid'].should == 'foo'
        auth['info'].should be_kind_of(Hash)
        auth['info']['groups'].sort.should == ["Developers", "jira-users"].sort
      end
    end

    context "when using session endpoint" do
      before do
        @use_sessions = true
        stub_request(:post, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/authentication?username=foo").
        to_return(:body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'success.xml')))
        stub_request(:post, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/session").
        to_return(:status => 201, :body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'session.xml')))
        stub_request(:get, "https://bogus_app:bogus_app_password@crowd.example.org/rest/usermanagement/latest/user/group/direct?username=foo").
        to_return(:body => File.read(File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'groups.xml')))
        get '/auth/crowd/callback', nil, 'rack.session'=>{'omniauth.crowd'=> {"username"=>"foo", "password"=>"ba"}}
      end

      after do
        @use_sessions = false
      end

      it 'should call through to the master app' do
        last_response.body.should == 'true'
      end

      it 'should have an auth hash' do
        auth = last_request.env['omniauth.auth']
        auth.should be_kind_of(Hash)
      end

      it 'should have good data' do
        auth = last_request.env['omniauth.auth']
        auth['provider'].should == :crowd
        auth['uid'].should == 'foo'
        auth['info'].should be_kind_of(Hash)
        auth['info']['sso_token'].should == 'rtk8eMvqq00EiGn5iJCMZQ00'
        auth['info']['groups'].sort.should == ["Developers", "jira-users"].sort
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
      last_response.should be_redirect
      last_response.headers['Location'].should =~ /invalid_credentials/
    end
  end
end
