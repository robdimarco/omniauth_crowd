require 'nokogiri'
require 'net/http'
require 'net/https'

module OmniAuth
  module Strategies
    class Crowd
      class CrowdValidator
        SESSION_REQUEST_BODY = <<-BODY.strip
<authentication-context>
  <username>%s</username>
  <password>%s</password>
</authentication-context>
BODY
        AUTHENTICATION_REQUEST_BODY = "<password><value>%s</value></password>"
        def initialize(configuration, username, password)
          @configuration, @username, @password = configuration, username, password
          @authentiction_uri = URI.parse(@configuration.authentication_url(@username))
          @session_uri       = URI.parse(@configuration.session_url) if @configuration.use_sessions
          @user_group_uri    = @configuration.include_users_groups? ? URI.parse(@configuration.user_group_url(@username)) : nil
        end

        def user_info
          user_info_hash = retrieve_user_info!
          if user_info_hash && @configuration.include_users_groups?
            user_info_hash = add_user_groups!(user_info_hash)
          else
            user_info_hash
          end

          if user_info_hash && @configuration.use_sessions?
            user_info_hash = add_session!(user_info_hash)
          end

          user_info_hash
        end

        private
        def add_session!(user_info_hash)
          response = make_session_request
          if response.kind_of?(Net::HTTPSuccess) && response.body
            doc = Nokogiri::XML(response.body)
            user_info_hash["sso_token"] = doc.xpath('//token/text()').to_s
          else
            OmniAuth.logger.send(:warn, "(crowd) [add_session!] response code: #{response.code.to_s}")
            OmniAuth.logger.send(:warn, "(crowd) [add_session!] response body: #{response.body}")
          end
          user_info_hash
        end

        def add_user_groups!(user_info_hash)
          response = make_user_group_request
          unless response.code.to_i != 200 || response.body.nil? || response.body == ''
            doc = Nokogiri::XML(response.body)
            user_info_hash["groups"] = doc.xpath("//groups/group/@name").map(&:to_s)
          end
          user_info_hash
        end

        def retrieve_user_info!
          response = make_authorization_request
          unless response.code.to_i != 200 || response.body.nil? || response.body == ''
            doc = Nokogiri::XML(response.body)
            {
              "user" => doc.xpath("//user/@name").to_s,
              "name" => doc.xpath("//user/display-name/text()").to_s,
              "first_name" => doc.xpath("//user/first-name/text()").to_s,
              "last_name" => doc.xpath("//user/last-name/text()").to_s,
              "email" => doc.xpath("//user/email/text()").to_s
            }
          else
            OmniAuth.logger.send(:warn, "(crowd) [retrieve_user_info!] response code: #{response.code.to_s}")
            OmniAuth.logger.send(:warn, "(crowd) [retrieve_user_info!] response body: #{response.body}")
            nil
          end
        end

        def make_request(uri, body=nil)
          http_method = body.nil? ? Net::HTTP::Get : Net::HTTP::Post
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.port == 443 || uri.instance_of?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl? && @configuration.disable_ssl_verification?
          http.start do |c|
            req = http_method.new(uri.query.nil? ? uri.path : "#{uri.path}?#{uri.query}")
            req.body = body if body
            req.basic_auth @configuration.crowd_application_name, @configuration.crowd_password
            req.add_field 'Content-Type', 'text/xml'
            http.request(req)
          end
        end

        def make_user_group_request
          make_request(@user_group_uri)
        end

        def make_authorization_request
          make_request(@authentiction_uri, make_authentication_request_body(@password))
        end

        def make_session_request
          make_request(@session_uri, make_session_request_body(@username, @password))
        end

        # create the body using Nokogiri so proper encoding of passwords can be ensured
        def make_authentication_request_body(password)
          request_body = Nokogiri::XML(AUTHENTICATION_REQUEST_BODY)
          password_value = request_body.at_css "value"
          password_value.content = password
          return request_body.root.to_s # return the body without the xml header
        end

        def make_session_request_body(username,password)
          request_body = Nokogiri::XML(SESSION_REQUEST_BODY)
          request_body.at_css("username").content = username
          request_body.at_css("password").content = password
          return request_body.root.to_s
        end
      end
    end
  end
end
