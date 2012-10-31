require 'nokogiri'
require 'net/http'
require 'net/https'

module OmniAuth
  module Strategies
    class Crowd
      class CrowdValidator
        AUTHENTICATION_REQUEST_BODY = "<password><value>%s</value></password>"
        def initialize(configuration, username, password)
          @configuration, @username, @password = configuration, username, password
          @authentiction_uri = URI.parse(@configuration.authentication_url(@username))
          @user_group_uri    = @configuration.include_users_groups? ? URI.parse(@configuration.user_group_url(@username)) : nil
        end

        def user_info
          user_info_hash = retrieve_user_info!
          if user_info_hash && @configuration.include_users_groups?
            user_info_hash = add_user_groups!(user_info_hash)
          else
            user_info_hash
          end
          user_info_hash
        end

        private
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
          OmniAuth.logger.send(:debug, "(crowd) retrieve_user_info! response code: #{response.code.to_s}")
          OmniAuth.logger.send(:debug, "(crowd) response body: #{response.body}")
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
            nil
          end
        end
        
        def make_user_group_request
          http = Net::HTTP.new(@user_group_uri.host, @user_group_uri.port)
          http.use_ssl = @user_group_uri.port == 443 || @user_group_uri.instance_of?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl? && @configuration.disable_ssl_verification?
          http.start do |c|
            req = Net::HTTP::Get.new("#{@user_group_uri.path}?#{@user_group_uri.query}")
            req.basic_auth @configuration.crowd_application_name, @configuration.crowd_password
            http.request(req)
          end
        end
        
        def make_authorization_request 
          http = Net::HTTP.new(@authentiction_uri.host, @authentiction_uri.port)
          http.use_ssl = @authentiction_uri.port == 443 || @authentiction_uri.instance_of?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl? && @configuration.disable_ssl_verification?
          http.start do |c|
            req = Net::HTTP::Post.new("#{@authentiction_uri.path}?#{@authentiction_uri.query}")
            req.body = make_authentication_request_body(@password)
            req.basic_auth @configuration.crowd_application_name, @configuration.crowd_password
            req.add_field 'Content-Type', 'text/xml'
            http.request(req)
          end
        end

        # create the body using Nokogiri so proper encoding of passwords can be ensured
        def make_authentication_request_body(password)
          request_body = Nokogiri::XML(AUTHENTICATION_REQUEST_BODY)
          password_value = request_body.at_css "value"
          password_value.content = password
          return request_body.root.to_s # return the body without the xml header
        end
      end
    end
  end
end
