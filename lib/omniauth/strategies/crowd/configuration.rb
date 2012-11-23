require 'rack'

module OmniAuth
  module Strategies
    class Crowd
      class Configuration
        DEFAULT_SESSION_URL = "%s/rest/usermanagement/latest/session"
        DEFAULT_AUTHENTICATION_URL = "%s/rest/usermanagement/latest/authentication"
        DEFAULT_USER_GROUP_URL = "%s/rest/usermanagement/latest/user/group/direct"
        attr_reader :crowd_application_name, :crowd_password, :disable_ssl_verification, :include_users_groups, :use_sessions, :session_url

        alias :"disable_ssl_verification?" :disable_ssl_verification
        alias :"include_users_groups?" :include_users_groups
        
        # @param [Hash] params configuration options
        # @option params [String, nil] :crowd_server_url the Crowd server root URL; probably something like
        #         `https://crowd.mycompany.com` or `https://crowd.mycompany.com/crowd`; optional.
        # @option params [String, nil] :crowd_authentication_url (:crowd_server_url + '/rest/usermanagement/latest/authentication') the URL to which to
        #         use for authenication; optional if `:crowd_server_url` is specified,
        #         required otherwise.
        # @option params [String, nil] :application_name the application name specified in Crowd for this application, required.
        # @option params [String, nil] :application_password the application password specified in Crowd for this application, required.
        # @option params [Boolean, nil] :disable_ssl_verification disable verification for SSL cert,
        #         helpful when you developing with a fake cert.
        # @option params [Boolean, true] :   include a list of user groups when getting information ont he user
        # @option params [String, nil] :crowd_user_group_url (:crowd_server_url + '/rest/usermanagement/latest/user/group/direct') the URL to which to
        #         use for retrieving users groups optional if `:crowd_server_url` is specified, or if `:include_user_groups` is false
        #         required otherwise.
        def initialize(params)
          parse_params params
        end

        # Build a Crowd authentication URL from +username+.
        #
        # @param [String] username the username to validate 
        # 
        # @return [String] a URL like `https://crowd.myhost.com/crowd/rest/usermanagement/latest/authentication?username=USERNAME`
        def authentication_url(username)
          append_username @authentication_url, username
        end
        
        def user_group_url(username)
          @user_group_url.nil? ? nil : append_username( @user_group_url, username)
        end
        
        private
        def parse_params(options)
          options= {:include_user_groups => true}.merge(options || {})
          %w(application_name application_password).each do |opt|
            raise ArgumentError.new(":#{opt} MUST be provided") if options[opt.to_sym] == ""
          end
          @crowd_application_name = options[:application_name]
          @crowd_password         = options[:application_password]
          @use_sessions           = options[:session_based]

          unless options.include?(:crowd_server_url) || options.include?(:crowd_authentication_url)
            raise ArgumentError.new("Either :crowd_server_url or :crowd_authentication_url MUST be provided")
          end

          if @use_sessions
            @session_url            = options[:crowd_session_url] || DEFAULT_SESSION_URL % options[:crowd_server_url]
            validate_is_url 'session URL', @session_url
          end
          @authentication_url     = options[:crowd_authentication_url] || DEFAULT_AUTHENTICATION_URL % options[:crowd_server_url]
          validate_is_url 'authentication URL', @authentication_url
          @disable_ssl_verification = options[:disable_ssl_verification]
          @include_users_groups     = options[:include_user_groups]
          if @include_users_groups
            @user_group_url         = options[:crowd_user_group_url] || DEFAULT_USER_GROUP_URL % options[:crowd_server_url]
            validate_is_url 'user group URL', @user_group_url
          end

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
