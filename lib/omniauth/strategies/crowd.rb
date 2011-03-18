require 'omniauth/core'

module OmniAuth
  module Strategies
    class Crowd
      include OmniAuth::Strategy
      autoload :Configuration, 'omniauth/strategies/crowd/configuration'
      autoload :CrowdValidator, 'omniauth/strategies/crowd/crowd_validator'
      def initialize(app, options = {}, &block)
        super(app, options[:name] || :crowd, options.dup, &block)
        @configuration = OmniAuth::Strategies::Crowd::Configuration.new(options)
      end
      
      protected
      
      def request_phase
        if env['REQUEST_METHOD'] == 'GET'
          get_credentials
        else
          session['omniauth.crowd'] = {'username' => request['username'], 'password' => request['password']}
          redirect callback_path
        end
      end

  	  def get_credentials
        OmniAuth::Form.build(:title => (options[:title] || "Crowd Authentication")) do
          text_field 'Login', 'username'
          password_field 'Password', 'password'
        end.to_response
      end

      def callback_phase 
        creds = session.delete 'omniauth.crowd'
        validator = CrowdValidator.new(@configuration, creds['username'], creds['password'])
        @user_info = validator.user_info
        
        return fail!(:invalid_credentials) if @user_info.nil? || @user_info.empty?

        super
      end

      def auth_hash
        OmniAuth::Utils.deep_merge(super, {
          'uid' => @user_info.delete("user"),
          'user_info' => @user_info
        })
      end   
    end
  end
end
