require 'rack'

module OmniAuth
  module Strategies
    class Crowd
      class Configuration
        attr_reader :crowd_application_name, :crowd_password
        
        # @param [Hash] params configuration options
        # @option params [String, nil] :crowd_server_url the Crowd server root URL; probably something like
        #         `https://crowd.mycompany.com` or `https://crowd.mycompany.com/crowd`; optional.
        # @option params [String, nil] :crowd_authentication_url (:crowd_server_url + '/rest/usermanagement/latest/authentication') the URL to which to
        #         use for authenication; optional if `:crowd_server_url` is specified,
        #         required otherwise.
        # @option params [String, nil] :application_name the application name specified in Crowd for this application, required.
        # @option params [String, nil] :application_password the application password specified in Crowd for this application, required.
        # @option params [Boolean, nil] :disable_ssl_verification disable verification for SSL cert,
        # helpful when you developing with a fake cert.
        def initialize(params)
          parse_params params
        end

        # Build a Crowd authentication URL from +username+.
        #
        # @param [String] username the username to validate 
        # 
        # @return [String] a URL like `http://cas.mycompany.com/login?service=...`
        def authentication_url(username)
          append_username @authentication_url, username
        end

        def disable_ssl_verification?
          @disable_ssl_verification
        end
        
        private
        DEFAULT_AUTHENTICATION_URL = "%s/rest/usermanagement/latest/authentication"
        def parse_params(options)
          %w(application_name application_password).each do |opt|
            raise ArgumentError.new(":#{opt} MUST be provided") if options[opt.to_sym].blank?
          end
          @crowd_application_name = options[:application_name]
          @crowd_password         = options[:application_password]

          unless options.include?(:crowd_server_url) or options.include?(:crowd_authentication_url)
            raise ArgumentError.new("Either :crowd_server_url or :crowd_authentication_url MUST be provided")
          end
          @authentication_url     = options[:crowd_authentication_url] || DEFAULT_AUTHENTICATION_URL % options[:crowd_server_url]
          validate_is_url 'authentication URL', @authentication_url

          @disable_ssl_verification = options[:disable_ssl_verification]
        end

        IS_NOT_URL_ERROR_MESSAGE = "%s is not a valid URL"

        def validate_is_url(name, possibly_a_url)
          url = URI.parse(possibly_a_url) rescue nil
          raise ArgumentError.new(IS_NOT_URL_ERROR_MESSAGE % name) unless url.kind_of?(URI::HTTP)
        end

        # Adds +service+ as an URL-escaped parameter to +base+.
        #
        # @param [String] base the base URL
        # @param [String] service the service (a.k.a. return-to) URL.
        #
        # @return [String] the new joined URL.
        def append_username(base, username)
          result = base.dup
          result << (result.include?('?') ? '&' : '?')
          result << 'username='
          result << Rack::Utils.escape(username)
        end
        
      end
    end
  end
end
