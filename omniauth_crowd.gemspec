# -*- encoding: utf-8 -*-
require File.expand_path('../lib/omniauth_crowd/version', __FILE__)
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.authors = ["Robert Di Marco"]
  gem.email = ["rob@innovationontherun.com"]
  gem.description = "This is an OmniAuth provider for Atlassian Crowd's REST API.  It allows you to easily integrate your Rack application in with Atlassian Crowd."
  gem.summary = "An OmniAuth provider for Atlassian Crowd REST API"
  gem.homepage = "http://github.com/robdimarco/omniauth_crowd"

  gem.executables = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files = `git ls-files`.split("\n")
  gem.test_files = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name = "omniauth_crowd"
  gem.require_paths = ["lib"]
  gem.version = OmniAuth::Crowd::VERSION

  gem.add_dependency 'omniauth', '~> 1.0'
  gem.add_dependency 'nokogiri', '>= 1.4.4'
  gem.add_development_dependency(%q<rack>, [">= 0"])
  gem.add_development_dependency(%q<rake>, [">= 0"])
  gem.add_development_dependency(%q<rack-test>, [">= 0"])
  gem.add_development_dependency(%q<rspec>, ["~> 3.0.0"])
  gem.add_development_dependency(%q<webmock>)
  gem.add_development_dependency(%q<bundler>, ["> 1.0.0"])
end
