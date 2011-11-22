require 'rubygems'
require 'rspec'
require 'rspec/autorun'
require 'rack/test'
require 'webmock/rspec'

include Rack::Test::Methods
include WebMock

require 'omniauth_crowd'

WebMock.disable_net_connect!
